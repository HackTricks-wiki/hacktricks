# 滥用 Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

如果你 **不知道什么是 Windows Access Tokens**，在继续之前请阅读此页面：


{{#ref}}
access-tokens.md
{{#endref}}

**也许你可以通过滥用你已经拥有的 tokens 来提升权限**

### SeImpersonatePrivilege

这是一个权限，任何持有该权限的进程都可以对任意 token 进行 impersonation（但不能创建 token），前提是能获得该 token 的句柄。可以通过诱使 Windows 服务（DCOM）对某个 exploit 执行 NTLM 认证来获取一个有特权的 token，从而以 SYSTEM 权限执行进程。该漏洞可以使用多种工具利用，例如 [juicy-potato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（需要禁用 winrm）、[SweetPotato](https://github.com/CCob/SweetPotato) 和 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer)。

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

它与 **SeImpersonatePrivilege** 非常相似，会使用 **相同的方法** 获取特权 token。  
随后，该权限允许 **将 primary token 分配** 给新的或挂起的进程。使用特权的 impersonation token 可以派生出 primary token（DuplicateTokenEx）。  
有了该 token，你可以使用 CreateProcessAsUser 创建 **新进程**，或者创建一个挂起的进程并 **设置 token**（通常你无法修改正在运行进程的 primary token）。

### SeTcbPrivilege

如果启用了此权限，你可以使用 **KERB_S4U_LOGON** 在不知凭据的情况下获取任何其他用户的 **impersonation token**，可以向该 token 添加任意组（例如 admins），将 token 的 **integrity level** 设置为“**medium**”，并将该 token 分配给 **当前线程**（SetThreadToken）。

### SeBackupPrivilege

该权限会使系统对任何文件授予全部**读取访问**（仅限读取操作）。它常用于从注册表读取本地 Administrator 帐户的密码哈希，随后可以用这些哈希配合工具如 **psexec** 或 **wmiexec**（Pass-the-Hash technique）进行利用。不过，这种方法在两种情况下会失败：本地 Administrator 帐户被禁用，或存在策略移除了远程连接时本地 Administrators 的管理权限。  
你可以使用以下方式**滥用该权限**：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- 参照 **IppSec** 的视频：[https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- 或者参见以下章节中关于 **escalating privileges with Backup Operators** 的说明：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

该权限授予对任何系统文件的**写访问权限**，无视文件的访问控制列表 (ACL)。这会带来多种提权可能性，包括能够 **修改服务**、进行 DLL Hijacking，以及通过 Image File Execution Options 设置 **debuggers** 等技术。

### SeCreateTokenPrivilege

SeCreateTokenPrivilege 是一项强大的权限，特别是在用户具备模拟 tokens 的能力时非常有用，即便没有 SeImpersonatePrivilege 也能发挥作用。该能力依赖于能够模拟表示相同用户且其 integrity level 不高于当前进程的 token。

**要点：**

- **无需 SeImpersonatePrivilege 的模拟：** 在特定条件下，可以利用 SeCreateTokenPrivilege 通过模拟 tokens 来实现 EoP。
- **Token 模拟的条件：** 成功的模拟要求目标 token 属于相同用户，且其 integrity level 小于或等于尝试模拟的进程的 integrity level。
- **创建与修改 impersonation tokens：** 用户可以创建一个 impersonation token，并通过添加特权组的 SID (Security Identifier) 来增强它。

### SeLoadDriverPrivilege

此权限允许通过创建带有特定 `ImagePath` 和 `Type` 值的注册表项来 **加载和卸载设备驱动**。由于对 `HKLM` (HKEY_LOCAL_MACHINE) 的直接写入被限制，因此必须改为使用 `HKCU` (HKEY_CURRENT_USER)。但要让内核识别 `HKCU` 用于驱动配置，需要遵循特定路径。

该路径为 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 是当前用户的 Relative Identifier。在 `HKCU` 中必须创建该完整路径，并设置两个值：

- `ImagePath`，即将要执行的二进制的路径
- `Type`，其值为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）

**步骤：**

1. 由于写入受限，使用 `HKCU` 而非 `HKLM`。
2. 在 `HKCU` 下创建路径 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 表示当前用户的 Relative Identifier。
3. 将 `ImagePath` 设置为要执行的二进制路径。
4. 将 `Type` 设为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。
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
有关滥用此权限的更多方法请见 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

这与 **SeRestorePrivilege** 类似。其主要功能是允许进程 **取得对象的所有权**，通过授予 WRITE_OWNER 访问权限来规避对显式自主访问的要求。该过程首先获取目标注册表项的所有权以便写入，然后修改 DACL 以启用写入操作。
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

此权限允许**调试其他进程**，包括读写内存。利用此权限可以采用多种内存注入策略，这些策略能够绕过大多数杀毒软件和主机入侵防护解决方案。

#### Dump memory

可以使用 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 来自 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) **捕获进程的内存**。特别是，这可以应用于 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 进程，该进程负责在用户成功登录系统后存储用户凭据。

然后可以在 mimikatz 中加载该转储以获取密码：
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

该权限 (Perform volume maintenance tasks) 允许打开原始卷设备句柄（例如 \\.\C:）以进行直接磁盘 I/O，从而绕过 NTFS ACLs。借助该权限，你可以通过读取底层区块来复制卷上任意文件的字节，从而实现对敏感资料的任意文件读取（例如机器私钥位于 %ProgramData%\Microsoft\Crypto\、注册表 hive、通过 VSS 获取的 SAM/NTDS）。这在 CA 服务器上尤其严重——窃取 CA 私钥可以伪造 Golden Certificate 来冒充任何主体。

参见详细技术与缓解措施：

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 检查权限
```
whoami /priv
```
显示为 **Disabled** 的 tokens 可以被启用，实际上你可以滥用 _Enabled_ 和 _Disabled_ tokens。

### 启用所有 tokens

如果你的 tokens 被禁用，你可以使用脚本 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 来启用所有 tokens：
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
或者在这篇 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) 中嵌入的 **脚本**。

## 表格

完整的 token 权限 备忘单在 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要仅列出利用这些权限直接获得 admin 会话或读取敏感文件的方式。

| 权限                       | Impact      | 工具                    | 执行路径                                                                                                                                                                                                                                                                                                                                      | 备注                                                                                                                                                                                                                                                                                                                            |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 第三方工具              | _"它允许用户模拟 token 并使用例如 potato.exe、rottenpotato.exe 和 juicypotato.exe 等工具对 nt system 进行 privesc"_                                                                                                                                                                                                                         | 感谢 [Aurélien Chalot](https://twitter.com/Defte_) 的更新。我会尽快把它改写得更像可执行的操作步骤。                                                                                                                                                                                                                                 |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | 使用 `robocopy /b` 读取敏感文件                                                                                                                                                                                                                                                                                                              | <p>- 如果你能读取 %WINDIR%\MEMORY.DMP，可能会更有价值。<br><br>- <code>SeBackupPrivilege</code>（和 robocopy）在处理已打开的文件时无效。<br><br>- 要使 Robocopy 的 /b 参数生效，需要同时拥有 SeBackup 和 SeRestore。</p>                                                                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | 第三方工具              | 使用 `NtCreateToken` 创建任意 token（包括本地 admin 权限）。                                                                                                                                                                                                                                                                                |                                                                                                                                                                                                                                                                                                                                  |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | 复制 `lsass.exe` 的 token。                                                                                                                                                                                                                                                                                                                  | 脚本可在 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) 找到。                                                                                                                                                                                                                      |
| **`SeLoadDriver`**         | _**Admin**_ | 第三方工具              | <p>1. 加载有漏洞的内核驱动，例如 <code>szkg64.sys</code><br>2. 利用该驱动漏洞<br><br>或者，该权限也可用于使用内置命令 <code>ftlMC</code> 卸载与安全相关的驱动。例如： <code>fltMC sysmondrv</code></p>                                                                                                                                            | <p>1. <code>szkg64</code> 漏洞被列为 <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. <code>szkg64</code> 的 <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> 由 <a href="https://twitter.com/parvezghh">Parvez Anwar</a> 创建</p>                                                                 |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. 以包含 SeRestore 权限的身份启动 PowerShell/ISE。<br>2. 使用 <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> 启用该权限。<br>3. 将 utilman.exe 重命名为 utilman.old<br>4. 将 cmd.exe 重命名为 utilman.exe<br>5. 锁定控制台并按 Win+U</p> | <p>某些 AV 软件可能会检测到该攻击。</p><p>替代方法是利用相同权限替换存放在 "Program Files" 的服务二进制文件</p>                                                                                                                                                                                                                   |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将 cmd.exe 重命名为 utilman.exe<br>4. 锁定控制台并按 Win+U</p>                                                                                                                                       | <p>某些 AV 软件可能会检测到该攻击。</p><p>替代方法是利用相同权限替换存放在 "Program Files" 的服务二进制文件。</p>                                                                                                                                                                                                                       |
| **`SeTcb`**                | _**Admin**_ | 第三方工具              | <p>操作 token 以包含本地 admin 权限。可能需要 SeImpersonate。</p><p>待验证。</p>                                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                  |

## 参考

- 请查看定义 Windows tokens 的表格： [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- 请查看关于使用 tokens 进行 privesc 的 [**this paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)。
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
