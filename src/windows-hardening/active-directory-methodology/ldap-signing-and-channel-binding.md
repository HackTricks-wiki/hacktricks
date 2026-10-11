# LDAP 签名与通道绑定加固

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 攻击会将身份验证转发到域控制器，以获取经过身份验证的 LDAP 上下文。两项相关控制可减少这类攻击路径：

- **LDAP 通道绑定 (CBT)** 将适用的身份验证绑定到 LDAPS 使用的 TLS 服务器证书/通道，阻碍跨通道 relay。
- **LDAP 签名** 要求 SASL LDAP bind 具有完整性保护。它不会增加机密性；如果 LDAP 内容也需要加密，请使用 TLS。<sup>[[2]](#references)</sup>

**快速检查安全状况**：`netexec ldap <dc> -u user -p pass` 等工具会报告检测到的签名和通道绑定策略。`(signing:None)` 和 `(channel binding:Never)` 表示缺少相关控制，但 relay 是否成功仍取决于捕获的身份验证类型、EPA 行为、账户权限、目标协议以及 relay 防护。如果被 relay 的主体拥有必要权限，KrbRelayUp 等工具可以写入 `msDS-AllowedToActOnBehalfOfOtherIdentity`、配置基于资源的约束委派 (RBCD)，并利用由此产生的委派路径模拟高权限主体。<sup>[[4]](#references)</sup>

**Server 2025 DC** 引入了新的 GPO（**LDAP 服务器签名要求强制执行**），当其保持 **Not Configured** 时，默认采用 **Require Signing**。若要避免强制执行，必须明确将该策略设为 **Disabled**。<sup>[[1]](#references)</sup>

## LDAP 通道绑定（仅限 LDAPS）

- **要求**：
  - CVE-2017-8563 补丁（2017）增加了对身份验证扩展保护的支持。<sup>[[3]](#references)</sup>
  - **KB4520412**（Server 2019/2022）增加了 LDAPS CBT 的“what-if”遥测。<sup>[[2]](#references)</sup>
- **GPO（DC）**：`Domain controller: LDAP server channel binding token requirements`
  - `Never`（默认，不使用 CBT）
  - `When Supported`（部分强制：支持 CBT 的客户端必须提供有效令牌；不支持 CBT 的客户端仍可 bind，并会生成审计事件）
  - `Always`（强制：拒绝缺少有效 CBT 的 LDAPS bind）<sup>[[1]](#references)</sup>
- **审计**：设为 **When Supported** 可发现以下情况：
  - **3074** – 如果启用强制，LDAPS bind 会因 CBT 验证失败。
  - **3075** – LDAPS bind 未提供 CBT 数据；如果启用强制，将会被拒绝。
  - （较旧版本中的事件 **3039** 仍表示 CBT 失败。）<sup>[[1]](#references)[[2]](#references)</sup>
- **强制执行**：LDAPS 客户端开始发送 CBT 后，设为 **Always**；此设置仅对 **LDAPS** 有效（不适用于原始 389）。<sup>[[1]](#references)</sup>

`When Supported` 不仅用于审计：它会验证支持 CBT 的客户端，同时允许不支持 CBT 的客户端连接。[Microsoft 策略参考](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)说明了该设置因版本而异的默认值。LDAP 签名适用于 LDAP/389 上符合条件的 bind；通道绑定则适用于受 TLS 保护的 LDAP 身份验证。


## LDAP 签名

- **客户端 GPO**：`Network security: LDAP client signing requirements` = `Require signing`（现代 Windows 上的默认值为 `Negotiate signing`）。<sup>[[1]](#references)</sup>
- **DC GPO**：
  - 旧版：`Domain controller: LDAP server signing requirements` = `Require signing`（默认值为 `None`）。<sup>[[2]](#references)</sup>
  - **Server 2025**：将旧版策略保留为 `None`，并将 `LDAP server signing requirements Enforcement` 设为 `Enabled`（默认会强制执行 Not Configured；若要避免强制执行，请设为 `Disabled`）。<sup>[[1]](#references)</sup>
- **兼容性**：盘点使用 simple bind 或未签名 SASL bind 的非 Windows 设备和应用程序。Microsoft 文档说明了受维护 Windows 版本上的支持情况；对于旧版客户端的兼容性声明，应根据实际客户端堆栈进行验证，而不要简化为 XP 版本门槛。<sup>[[2]](#references)</sup>

## 先审计再逐步推出（建议约 30 天）

1. 在每台 DC 上启用 LDAP 接口诊断，以记录未签名 bind（事件 **2889**）：<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. 将 DC GPO `LDAP server channel binding token requirements` 设置为 **When Supported**，以进行部分 CBT 强制和遥测；先验证与旧版客户端的兼容性。<sup>[[1]](#references)</sup>
3. 监控 Directory Service 事件：<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – 未签名/允许未签名的 bind（不符合签名要求）。
   - **3074/3075** – 将会失败或缺少 CBT 的 LDAPS bind（在 2019/2022 上需要 KB4520412 及上述第 2 步）。
4. 分别进行以下强制措施：<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always**（DC）。
   - `LDAP client signing requirements` = **Require signing**（客户端）。
   - `LDAP server signing requirements` = **Require signing**（DC），**或**（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。

## References

- [1] [TrustedSec - LDAP 通道绑定与 LDAP 签名](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP 通道绑定与签名要求](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay 缓解更新](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno（LDAP signing 已禁用 → Kerberos relay → RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
{{#include ../../banners/hacktricks-training.md}}
