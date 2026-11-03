# LDAP Signing & Channel Binding 加固

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 攻击会将身份验证转发到域控制器，以获取已验证的 LDAP 上下文。[名称解析投毒和 relay 概述](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)介绍了更广泛的攻击流程。两项相关控制措施可以减少这些攻击路径：

- **LDAP channel binding (CBT)** 将适用的身份验证绑定到 LDAPS 所用的 TLS 服务器证书/通道，从而阻碍跨通道 relay。
- **LDAP signing** 要求 SASL LDAP bind 具备完整性保护。它不会提供机密性；如果 LDAP 内容也需要加密，请使用 TLS。<sup>[[2]](#references)</sup>

**快速检查安全状态**：`netexec ldap <dc> -u user -p pass` 等工具会报告检测到的 signing 和 channel-binding 策略。`(signing:None)` 和 `(channel binding:Never)` 表明缺少相应控制措施，但 relay 能否成功仍取决于捕获的身份验证类型、EPA 行为、账户权限、目标协议和 relay 防护措施。如果被 relay 的主体具有必要权限，KrbRelayUp 等工具可以写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`、配置基于资源的约束委派 (RBCD)，并利用由此产生的委派路径来冒充特权主体。<sup>[[4]](#references)</sup>

**Server 2025 DC** 引入了一项新的 GPO（**LDAP server signing requirements Enforcement**）；如果该策略保持 **Not Configured**，默认值为 **Require Signing**。若要避免强制执行，必须明确将该策略设为 **Disabled**。<sup>[[1]](#references)</sup>

## LDAP Channel Binding（仅限 LDAPS）

- **要求**：
  - CVE-2017-8563 补丁（2017）增加了对 Extended Protection for Authentication 的支持。<sup>[[3]](#references)</sup>
  - **KB4520412**（Server 2019/2022）为 LDAPS CBT 增加了“what-if”遥测。<sup>[[2]](#references)</sup>
- **GPO（DC）**：`Domain controller: LDAP server channel binding token requirements`
  - `Never`（默认值，不使用 CBT）
  - `When Supported`（部分强制：支持 CBT 的客户端必须提供有效 token；不支持 CBT 的客户端仍可 bind，并会生成审核事件）
  - `Always`（强制：拒绝缺少有效 CBT 的 LDAPS bind）<sup>[[1]](#references)</sup>
- **审核**：设为 **When Supported** 以发现以下情况：
  - **3074** – 如果启用强制执行，该 LDAPS bind 将无法通过 CBT 验证。
  - **3075** – 该 LDAPS bind 未提供 CBT 数据；如果启用强制执行，将被拒绝。
  - （较旧版本上的事件 **3039** 仍表示 CBT 验证失败。）<sup>[[1]](#references)[[2]](#references)</sup>
- **强制执行**：LDAPS 客户端开始发送 CBT 后，设为 **Always**；该设置仅对 **LDAPS** 生效（不适用于原始 389 端口）。<sup>[[1]](#references)</sup>

`When Supported` 并非仅用于审核：它会验证支持 CBT 的客户端，同时允许不支持 CBT 的客户端连接。[Microsoft 策略参考](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)说明了其随版本变化的默认值。LDAP signing 适用于 LDAP/389 上相应的 bind；channel binding 适用于受 TLS 保护的 LDAP 身份验证。

## LDAP Signing

- **客户端 GPO**：`Network security: LDAP client signing requirements` = `Require signing`（现代 Windows 上的默认值为 `Negotiate signing`）。<sup>[[1]](#references)</sup>
- **DC GPO**：
  - 旧版：`Domain controller: LDAP server signing requirements` = `Require signing`（默认值为 `None`）。<sup>[[2]](#references)</sup>
  - **Server 2025**：将旧版策略保留为 `None`，并将 `LDAP server signing requirements Enforcement` 设为 `Enabled`（默认情况下，Not Configured 表示强制执行；若要避免强制执行，请设为 `Disabled`）。<sup>[[1]](#references)</sup>
- **兼容性**：盘点使用 simple bind 或未签名 SASL bind 的非 Windows 设备和应用程序。Microsoft 记录了受维护 Windows 版本上的支持情况；应根据实际客户端栈核实旧版客户端的兼容性说明，而不要将其简化为 XP 版本门槛。<sup>[[2]](#references)</sup>

## Relay 路径与 signed-SASL 重新身份验证

如果**仅要求 signing**，在未强制执行 channel binding 时，relay 到 LDAPS 仍可能成功：TLS 会提供传输完整性。如果**仅要求 channel binding**，普通 LDAP 没有可供绑定的 TLS 通道；relay 可以先在 TCP 389 上完成身份验证，然后对需要 TLS 的操作使用 StartTLS，前提是被 relay 的身份具有必要权限。强制执行两项控制可以封堵这些常见替代路径，但无法阻止未修补的域控制器上的以下漏洞。<sup>[[5]](#references)</sup>

### 在 relay 的 Bind 后叠加 LDAP 操作

在受影响的 Windows Server 2016–2025 域控制器上，首先以身份 X 在 TCP 389 上建立**已签名的 NTLM SASL LDAP 连接**，使用你知道其 session key 的凭据（或使用在该环境中被接受的匿名 NTLM SASL 上下文）。诱使身份 Y 通过 **SMB** 向 relay 进行身份验证。通过 X 现有的 LDAP 连接上的 GSS-SPNEGO Bind 请求，转发 Y 的 NTLM NEGOTIATE 和 DC 的 CHALLENGE。Windows SMB 客户端会设置 `NTLMSSP_NEGOTIATE_SIGN`，因此生成的 LDAP bind 需要 signed SASL 层；源自 HTTP/WebDAV 的交换通常不含该标志，因此在此处不可互换。<sup>[[5]](#references)</sup>

Y 发送 NTLM AUTHENTICATE 时，在**一个带长度前缀的 SASL 记录中放入两条不同的 LDAP 消息**：一条携带该响应的 BindRequest，后接一条 ModifyRequest。使用 X 已知的 key 对整条记录签名。存在漏洞的 DC 会使用 X 的凭据验证该记录，完成 Bind 并将连接的授权身份切换为 Y，然后以 Y 的身份执行剩余的 ModifyRequest，而不会再使用 Y 的 key 验证该记录。这不会泄露 Y 的密码或 session key；之后由 X 签名的记录会验证失败。对 `msDS-AllowedToActOnBehalfOfOtherIdentity` 的 RBCD 写入，或对 `msDS-KeyCredentialLink` 的 shadow credential 写入，仍要求 Y 对目标对象拥有相应权限。请参阅 [RBCD](resource-based-constrained-delegation.md)、[shadow credentials](acl-persistence-abuse/shadow-credentials.md)，以及在 relay 的对象为 DC 机器账户时的 [DCSync](dcsync.md)。<sup>[[5]](#references)</sup>

这是 **plain LDAP** 绕过，不是 LDAPS channel-binding 绕过。在 LDAPS 上，TLS 会保护连接，而 Windows 不会建立此记录叠加路径所需的 X-key NTLM SASL signing 层。如果 TCP 389 不可用，该技术不能直接转移到 TCP 636。2026 年 10 月的安全更新会在 Bind 更改连接身份后丢弃剩余数据，从而阻止同一记录中的操作。<sup>[[5]](#references)</sup> KB5126646 是 Windows Server 2025 的更新；其他受影响的 Server 版本使用不同的 KB 编号。<sup>[[7]](#references)</sup>

研究人员的 [LDAP Switcheroo](https://github.com/grayhatkiller/switcheroo) 为此工作流封装了修改版 `ntlmrelayx.py`。它需要一个 **SMB** 强制认证来源、一个公开 LDAP signing/security-context API 的固定版本 Impacket 代码树（PyPI 上的 Impacket 0.13.1 不满足要求），以及一个由攻击者控制、用于初始 signed bind 的账户。若要执行 RBCD 写入，请提供受害对象的 DN 和一个受控委派计算机的 SID；若要执行其他允许的写入，请使用 `-attribute` 搭配 `-value` 或 `-value-hex`。应确认工具独立执行的 signed read-back，不要仅凭 relay 侧的 `FAILED` 消息就认定 ModifyRequest 失败。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

单独触发 SMB 身份验证；有关一种强制身份验证的途径，请参阅[强制特权 NTLM 身份验证](printers-spooler-service-abuse.md)，有关其他途径，请参阅[中继概述](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)。该工具的命令和实现文档见其代码仓库。<sup>[[6]](#references)</sup>

## 先审计后推广（建议约 30 天）

1. 在每台 DC 上启用 LDAP 接口诊断，以记录未签名绑定（事件 **2889**）：<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. 将 DC GPO `LDAP server channel binding token requirements` 设置为 **When Supported**，以进行部分 CBT 强制和遥测；先验证与旧版客户端的兼容性。<sup>[[1]](#references)</sup>
3. 监控 Directory Service 事件：<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 未签名/允许未签名的绑定（不符合 signing 要求）。
   - **3074/3075** – 会失败或缺少 CBT 的 LDAPS 绑定（需要在 2019/2022 上安装 KB4520412，并完成上述第 2 步）。
4. 分别进行强制设置：<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（客户端）。
   - `LDAP server signing requirements` = **Require signing**（DC）**或**（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。



## References

- [1] [TrustedSec - LDAP 通道绑定与 LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 通道绑定与 Signing 要求](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 缓解更新](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP Signing 已禁用 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – 已签名、已密封与已中继：NTLM 风格](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo 概念验证](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Windows Server 发行信息](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
