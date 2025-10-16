# 滥用令牌

{{#include ../../banners/hacktricks-training.md}}

## 令牌

如果你 **不知道 Windows Access Tokens 是什么**，请在继续之前阅读此页：


{{#ref}}
access-tokens.md
{{#endref}}

**你可能能够通过滥用已拥有的令牌来提升权限**

### SeImpersonatePrivilege

这是一个权限，任何持有该权限的进程在获得相应句柄后可以对任意 token 进行 impersonation（但不能创建）。可以通过诱使 Windows 服务（DCOM）对一个利用链执行 NTLM 认证来获取特权 token，从而执行具有 SYSTEM 权限的进程。该方法可使用多种工具进行利用，例如 [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要禁用 winrm）、[SweetPotato](https://github.com/CCob/SweetPotato) 和 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

它与 **SeImpersonatePrivilege** 非常相似，会使用相同的方法来获取特权 token。\
随后，该权限允许 **将主令牌（primary token）分配给新建或挂起的进程**。使用特权的 impersonation token 可以派生出主令牌（DuplicateTokenEx）。\
有了该令牌，你可以使用 'CreateProcessAsUser' 创建 **新进程**，或者创建一个挂起的进程并 **设置令牌**（通常不能修改正在运行进程的主令牌）。

### SeTcbPrivilege

如果启用了此权限，你可以使用 **KERB_S4U_LOGON** 在不知晓凭据的情况下获取任意用户的 **impersonation token**，向令牌中 **添加任意组**（例如 admins），将令牌的 **integrity level** 设置为 “**medium**”，并将该令牌分配给 **当前线程**（SetThreadToken）。

### SeBackupPrivilege

此权限会使系统对任意文件授予 **全部读取访问**（仅限读取操作）。它通常用于 **从注册表读取本地 Administrator 的密码哈希**，随后可以使用例如 **psexec** 或 **wmiexec** 之类的工具配合哈希进行登录（Pass-the-Hash 技术）。不过，当本地 Administrator 帐户被禁用，或存在移除远程连接时本地 Administrators 管理权限的策略时，此技术会失效。\
你可以通过以下方式 **滥用此权限**：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- 按照 **IppSec** 在 [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) 的演示
- 或者如以下章节中所述，关于如何通过 Backup Operators 提权：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

该权限允许对任意系统文件进行 **写访问**，而不考虑文件的访问控制列表（ACL）。这开启了多种提权途径，包括 **修改服务**、DLL Hijacking、通过 Image File Execution Options 设置 **调试器（debuggers）** 等技术。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege 是一个强大的权限，尤其在用户能够 impersonate token 时非常有用，但即便在没有 SeImpersonatePrivilege 的情况下也可发挥作用。该能力依赖于能够 impersonate 一个表示相同用户且完整性级别（integrity level）不高于当前进程的令牌。

关键点：

- 在没有 SeImpersonatePrivilege 的情况下进行 impersonation：可以在特定条件下利用 SeCreateTokenPrivilege 实现 EoP。
- 令牌模拟的条件：成功的模拟要求目标令牌属于相同用户，且其完整性级别小于或等于尝试模拟的进程的完整性级别。
- 创建和修改 impersonation 令牌：可以创建一个 impersonation 令牌，并通过添加有特权组的 SID（Security Identifier）来增强该令牌。

### SeLoadDriverPrivilege

该权限允许通过创建注册表项并设置 `ImagePath` 和 `Type` 的特定值来 **加载和卸载设备驱动**。由于对 `HKLM`（HKEY_LOCAL_MACHINE）的直接写入受限，必须使用 `HKCU`（HKEY_CURRENT_USER）。然而，要使内核识别用于驱动配置的 `HKCU`，必须遵循特定路径。

该路径为 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 是当前用户的相对标识符（Relative Identifier）。在 `HKCU` 中需要创建该完整路径，并设置两个值：

- `ImagePath`，即要执行的二进制文件路径
- `Type`，其值为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。

操作步骤：

1. 由于写入受限，访问 `HKCU` 而不是 `HKLM`。
2. 在 `HKCU` 中创建路径 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 表示当前用户的相对标识符。
3. 将 `ImagePath` 设置为要执行的二进制路径。
4. 将 `Type` 赋值为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
更多滥用该权限的方法见 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

这类似于 **SeRestorePrivilege**。其主要功能允许进程**取得对象的所有权**，通过提供 WRITE_OWNER 访问权限绕过对显式任意访问的要求。该过程首先获取目标注册表项的所有权以便写入，随后修改 DACL 以启用写操作。
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

此权限允许对 **debug other processes**，包括读取和写入进程的 memory。利用该权限可以采用多种 memory injection 策略，这些策略能够规避大多数 antivirus 和 host intrusion prevention 解决方案。

#### Dump memory

可以使用 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)（来自 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)）来**capture the memory of a process**。具体而言，这通常适用于 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 进程，该进程负责在用户成功登录系统后存储用户凭据。

然后可以在 mimikatz 中加载该 dump 以获取密码：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

如果你想获得一个 `NT SYSTEM` shell，你可以使用：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

此权限 (Perform volume maintenance tasks) 允许打开原始卷设备句柄（例如 \\.\C:）以进行直接磁盘 I/O，从而绕过 NTFS ACLs。凭此权限，你可以通过读取底层块复制卷上任意文件的字节，从而实现对敏感资料的任意文件读取（例如位于 %ProgramData%\Microsoft\Crypto\ 的机器私钥、registry hives、通过 VSS 获取的 SAM/NTDS）。这在 CA servers 上尤其有影响：窃取 CA 私钥可用于伪造 Golden Certificate，从而冒充任何主体。

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 检查权限
```
whoami /priv
```
显示为 **Disabled** 的令牌可以被启用，实际上你可以滥用 _Enabled_ 和 _Disabled_ 令牌。

### 启用所有令牌

如果你有被禁用的令牌，你可以使用脚本 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 来启用所有令牌：
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embed in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## 表格

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 第三方工具              | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | 感谢 [Aurélien Chalot](https://twitter.com/Defte_) 的更新。我会尽快把它改写得更像步骤式的配方。                                                                                                                                                                                                                                     |
| **`SeBackup`**             | **威胁**    | _**Built-in commands**_ | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- May be more interesting if you can read %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (and robocopy) is not helpful when it comes to open files.<br><br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 第三方工具              | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                                   | 脚本见 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                                          |
| **`SeLoadDriver`**         | _**Admin**_ | 第三方工具              | <p>1. Load buggy kernel driver such as <code>szkg64.sys</code><br>2. Exploit the driver vulnerability<br><br>Alternatively, the privilege may be used to unload security-related drivers with <code>ftlMC</code> builtin command. i.e.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. The <code>szkg64</code> vulnerability is listed as <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. The <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> was created by <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Launch PowerShell/ISE with the SeRestore privilege present.<br>2. Enable the privilege with <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Rename utilman.exe to utilman.old<br>4. Rename cmd.exe to utilman.exe<br>5. Lock the console and press Win+U</p> | <p>该攻击可能会被某些 AV 软件检测到。</p><p>替代方法是使用相同权限替换存储在 "Program Files" 中的 service 二进制文件</p>                                                                                                                                                                                                               |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Rename cmd.exe to utilman.exe<br>4. Lock the console and press Win+U</p>                                                                                                                                       | <p>该攻击可能会被某些 AV 软件检测到。</p><p>替代方法是使用相同权限替换存储在 "Program Files" 中的 service 二进制文件。</p>                                                                                                                                                                                                                       |
| **`SeTcb`**                | _**Admin**_ | 第三方工具              | <p>Manipulate tokens to have local admin rights included. May require SeImpersonate.</p><p>To be verified.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## 参考

- 查看定义 Windows tokens 的表格: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Take a look to [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) about privesc with tokens.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
