# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 让攻击者能够将 binds 转发到 Domain Controllers 以获取已认证的上下文。有两项服务器端控制可以削弱这些路径：

- **LDAP Channel Binding (CBT)** 将 LDAPS bind 绑定到特定的 TLS 通道，阻止跨不同通道的中继/重放。
- **LDAP Signing** 强制对 LDAP 消息进行完整性保护，防止篡改和大多数未签名的中继。

**快速进攻性检查**：像 `netexec ldap <dc> -u user -p pass` 这样的工具会打印服务器姿态。如果你看到 `(signing:None)` 和 `(channel binding:Never)`，Kerberos/NTLM **relays to LDAP** 是可行的（例如使用 KrbRelayUp 写入 `msDS-AllowedToActOnBehalfOfOtherIdentity` 来做 RBCD 并模拟管理员）。

**Server 2025 DCs** 引入了一个新的 GPO (**LDAP server signing requirements Enforcement**)，当保持 **Not Configured** 时默认为 **Require Signing**。要避免被强制执行，你必须显式将该策略设置为 **Disabled**。

## LDAP Channel Binding (LDAPS only)

- **Requirements**:
- CVE-2017-8563 补丁（2017）增加了 Extended Protection for Authentication 支持。
- **KB4520412**（Server 2019/2022）增加了 LDAPS CBT “what-if” 遥测。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (default, no CBT)
- `When Supported` (audit: emits failures, does not block)
- `Always` (enforce: rejects LDAPS binds without valid CBT)
- **Audit**: 将 **When Supported** 设置为以揭示：
- **3074** – 如果强制执行，LDAPS bind 在 CBT 验证时本会失败。
- **3075** – LDAPS bind 省略了 CBT 数据，如果强制执行将被拒绝。
- (Event **3039** 在较旧的构建上仍然表示 CBT 失败。)
- **Enforcement**: 一旦 LDAPS 客户端发送 CBT，就将其设置为 **Always**；仅对 **LDAPS** 生效（不适用于原始 389）。

## LDAP Signing

- **Client GPO**: `Network security: LDAP client signing requirements` = `Require signing` (vs `Negotiate signing` default on modern Windows).
- **DC GPO**:
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing` (default is `None`).
- **Server 2025**: 将 legacy 策略保持为 `None` 并将 `LDAP server signing requirements Enforcement` = `Enabled`（Not Configured = 默认被强制；将其设置为 `Disabled` 以避免）。
- **Compatibility**: 只有 Windows **XP SP3+** 支持 LDAP signing；在启用强制时，较旧的系统将会中断。

## Audit-first rollout (recommended ~30 days)

1. 在每个 DC 上启用 LDAP 接口诊断以记录未签名的 binds (Event **2889**):
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. 将 DC GPO `LDAP server channel binding token requirements` = **When Supported** 以启动 CBT 遥测。
3. 监视 Directory Service 事件：
- **2889** – unsigned/unsigned-allow 绑定（签名不合规）。
- **3074/3075** – 会失败或省略 CBT 的 LDAPS 绑定（在 2019/2022 上需要 KB4520412 并且需要上述步骤 2）。
4. 在单独的变更中强制执行：
- `LDAP server channel binding token requirements` = **Always** (DCs).
- `LDAP client signing requirements` = **Require signing** (clients).
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.

## 参考资料

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
