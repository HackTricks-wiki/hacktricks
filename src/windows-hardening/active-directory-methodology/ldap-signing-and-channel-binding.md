# LDAP Signing & Channel Binding 加固

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 允许攻击者将 binds 转发到域控制器以获取已认证的上下文。两项服务器端控制可以阻断这些途径：

- **LDAP Channel Binding (CBT)** ties an LDAPS bind to the specific TLS tunnel, breaking relays/replays across different channels.
- **LDAP Signing** 强制对 LDAP 消息进行完整性保护，防止篡改和大多数未签名的中继。

**Quick offensive check**：像 `netexec ldap <dc> -u user -p pass` 这样的工具会打印服务器姿态。如果你看到 `(signing:None)` 和 `(channel binding:Never)`，Kerberos/NTLM **relays to LDAP** 是可行的（例如，使用 KrbRelayUp 写入 `msDS-AllowedToActOnBehalfOfOtherIdentity` 用于 RBCD 并冒充管理员）。

**Server 2025 DCs** 引入了一个新的 GPO（**LDAP server signing requirements Enforcement**），当保留为 **Not Configured** 时默认变为 **Require Signing**。要避免被强制执行，必须显式将该策略设置为 **Disabled**。

## LDAP Channel Binding (仅限 LDAPS)

- **要求**：
- CVE-2017-8563 补丁（2017）为 Extended Protection for Authentication 添加了支持。
- **KB4520412** (Server 2019/2022) 为 LDAPS CBT 添加了“what-if”遥测。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (默认，无 CBT)
- `When Supported` (审计：记录失败，但不阻止)
- `Always` (强制：拒绝没有有效 CBT 的 LDAPS bind)
- **审计**：将 **When Supported** 设置为以便显示：
- **3074** – 如果强制，LDAPS bind 在 CBT 验证中会失败。
- **3075** – LDAPS bind 省略了 CBT 数据，如果强制会被拒绝。
-（事件 **3039** 在较旧的版本上仍然会标示 CBT 失败。）
- **强制执行**：一旦 LDAPS 客户端发送 CBTs，将其设置为 **Always**；仅对 **LDAPS** 生效（不适用于裸 389）。

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing`（与现代 Windows 的默认 `Negotiate signing` 相比）。
- **DC GPO**：
- Legacy：`Domain controller: LDAP server signing requirements` = `Require signing`（默认为 `None`）。
- **Server 2025**：将 legacy 策略保持为 `None`，并将 `LDAP server signing requirements Enforcement` = `Enabled`（Not Configured = enforced by default；将其设置为 `Disabled` 以避免强制）。
- **兼容性**：只有 Windows **XP SP3+** 支持 LDAP signing；在启用强制后旧系统将会中断。

## 先审计再部署（建议约 30 天）

1. 在每台 DC 上启用 LDAP 接口诊断以记录未签名的 binds（事件 **2889**）：
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. 将 DC GPO `LDAP server channel binding token requirements` 设为 **When Supported** 以开始 CBT 遥测。
3. 监控 Directory Service 事件：
- **2889** – unsigned/unsigned-allow binds（签名不合规）。
- **3074/3075** – LDAPS binds 会失败或省略 CBT（在 2019/2022 上需要 KB4520412 且需先完成第 2 步）。
4. 分开实施强制更改：
- `LDAP server channel binding token requirements` = **Always** (DCs)。
- `LDAP client signing requirements` = **Require signing** (clients)。
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**。

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
