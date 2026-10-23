# LDAP 签名与通道绑定加固

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 攻击会将身份验证转发到域控制器，以获取经过身份验证的 LDAP 上下文。[名称解析投毒与 relay 概述](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)介绍了更广泛的攻击流程。两项相关控制措施可以减少这类攻击路径：

- **LDAP channel binding (CBT)** 将适用的身份验证绑定到 LDAPS 使用的 TLS 服务器证书/通道，从而阻碍跨通道 relay。
- **LDAP signing** 要求 SASL LDAP bind 提供完整性保护。它不提供机密性；如果还需要加密 LDAP 内容，请使用 TLS。<sup>[[2]](#references)</sup>

**快速检查安全状态**：`netexec ldap <dc> -u user -p pass` 等工具会报告检测到的 signing 和 channel-binding 策略。`(signing:None)` 和 `(channel binding:Never)` 表示缺少相应控制措施，但 relay 是否成功仍取决于捕获的身份验证类型、EPA 行为、账户权限、目标协议以及 relay 防护措施。如果被 relay 的主体拥有必要权限，KrbRelayUp 等工具可以写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`、配置基于资源的约束委派 (RBCD)，并利用由此产生的委派路径冒充特权主体。<sup>[[4]](#references)</sup>

**Server 2025 DC** 引入了一项新的 GPO（**LDAP server signing requirements Enforcement**）；若保持 **Not Configured**，默认值为 **Require Signing**。若要避免强制执行，必须将该策略显式设为 **Disabled**。<sup>[[1]](#references)</sup>

## LDAP 通道绑定（仅限 LDAPS）

- **要求**：
  - CVE-2017-8563 补丁（2017）增加了对 Extended Protection for Authentication 的支持。<sup>[[3]](#references)</sup>
  - **KB4520412**（Server 2019/2022）增加了 LDAPS CBT “what-if” 遥测。<sup>[[2]](#references)</sup>
- **GPO（DC）**：`Domain controller: LDAP server channel binding token requirements`
  - `Never`（默认，不使用 CBT）
  - `When Supported`（部分强制：支持 CBT 的客户端必须提供有效 token；不支持 CBT 的客户端仍可 bind，并会生成审计事件）
  - `Always`（强制：拒绝未提供有效 CBT 的 LDAPS bind）<sup>[[1]](#references)</sup>
- **审计**：设置为 **When Supported**，以便发现：
  - **3074** – 如果启用强制执行，该 LDAPS bind 会因 CBT 验证失败而被拒绝。
  - **3075** – 该 LDAPS bind 未提供 CBT 数据；如果启用强制执行，将被拒绝。
  - （在较旧的版本中，事件 **3039** 仍表示 CBT 验证失败。）<sup>[[1]](#references)[[2]](#references)</sup>
- **强制执行**：待 LDAPS 客户端开始发送 CBT 后，将其设为 **Always**；仅对 **LDAPS** 生效（不适用于原始 389 端口）。<sup>[[1]](#references)</sup>

`When Supported` 并非仅用于审计：它会验证支持 CBT 的客户端，同时允许不支持 CBT 的客户端连接。[Microsoft 策略参考](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)说明了该策略因版本而异的默认值。LDAP signing 适用于 LDAP/389 上符合条件的 bind；channel binding 适用于受 TLS 保护的 LDAP 身份验证。

## LDAP Signing

- **客户端 GPO**：`Network security: LDAP client signing requirements` = `Require signing`（现代 Windows 默认值为 `Negotiate signing`）。<sup>[[1]](#references)</sup>
- **DC GPO**：
  - 旧版：`Domain controller: LDAP server signing requirements` = `Require signing`（默认值为 `None`）。<sup>[[2]](#references)</sup>
  - **Server 2025**：将旧版策略保留为 `None`，并将 `LDAP server signing requirements Enforcement` 设为 `Enabled`（默认会强制执行 `Not Configured`；若要避免强制执行，请设为 `Disabled`）。<sup>[[1]](#references)</sup>
- **兼容性**：清点使用 simple bind 或未签名 SASL bind 的非 Windows 设备和应用程序。Microsoft 说明了受维护 Windows 版本上的支持情况；应根据实际客户端堆栈核实旧版客户端的兼容性说明，而不要简单地用 XP 版本作为判断门槛。<sup>[[2]](#references)</sup>

## 先审计再推出（建议约 30 天）

1. 在每个 DC 上启用 LDAP 接口诊断，以记录未签名的 bind（事件 **2889**）：<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. 将 DC GPO `LDAP server channel binding token requirements` 设为 **When Supported**，以进行部分 CBT 强制和遥测；先验证与旧版客户端的兼容性。<sup>[[1]](#references)</sup>
3. 监控 Directory Service 事件：<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 未签名/允许未签名的绑定（不符合签名要求）。
   - **3074/3075** – 将会失败或缺少 CBT 的 LDAPS 绑定（2019/2022 需要 KB4520412 和上面的第 2 步）。
4. 分别进行以下强制设置：<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（客户端）。
   - `LDAP server signing requirements` = **Require signing**（DC），**或**（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。



## References

- [1] [TrustedSec - LDAP 通道绑定与 LDAP 签名](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 通道绑定和签名要求](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 缓解更新](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP 签名已禁用 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
