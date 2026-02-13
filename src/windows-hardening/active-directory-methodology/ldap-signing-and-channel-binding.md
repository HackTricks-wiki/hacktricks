# LDAP Signing & Channel Binding 加固

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 允许攻击者将绑定转发到域控制器以获取已认证的上下文。两项服务器端控制可以阻断这些途径：

- **LDAP Channel Binding (CBT)** 将 LDAPS 绑定与特定的 TLS 隧道关联，阻断跨不同通道的中继/重放。
- **LDAP Signing** 强制 LDAP 消息使用完整性保护，防止篡改和大多数未签名的中继。

**Server 2025 DCs** 引入了一个新的 GPO (**LDAP server signing requirements Enforcement**)，当保持 **Not Configured** 时会默认设为 **Require Signing**。要避免被强制执行，必须将该策略显式设置为 **Disabled**。

## LDAP Channel Binding (仅 LDAPS)

- **要求**:
- CVE-2017-8563 补丁（2017）增加了对 Extended Protection for Authentication 的支持。
- **KB4520412**（Server 2019/2022）增加了 LDAPS CBT 的 “what-if” 遥测。
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
- `Never` (默认，不启用 CBT)
- `When Supported` (审计：记录失败，但不阻止)
- `Always` (强制：拒绝没有有效 CBT 的 LDAPS 绑定)
- **审计**：将 **When Supported** 设置为以暴露：
- **3074** – 如果强制，该 LDAPS 绑定在 CBT 验证上会失败。
- **3075** – 该 LDAPS 绑定省略了 CBT 数据，若强制将被拒绝。
- (在较旧的版本上，事件 **3039** 仍然表示 CBT 失败。)
- **强制执行**：一旦 LDAPS 客户端开始发送 CBT，将 **Always** 设置为启用；仅对 **LDAPS** 生效（不适用于原始 389）。

## LDAP 签名

- **Client GPO**：`Network security: LDAP client signing requirements` = `Require signing`（与现代 Windows 默认的 `Negotiate signing` 相比）。
- **DC GPO**：
- Legacy: `Domain controller: LDAP server signing requirements` = `Require signing`（默认是 `None`）。
- **Server 2025**：将旧策略保持为 `None` 并将 `LDAP server signing requirements Enforcement` 设置为 `Enabled`（Not Configured = 默认会被强制；将其设置为 `Disabled` 以避免强制）。
- **兼容性**：只有 Windows **XP SP3+** 支持 LDAP 签名；在启用强制时，较旧的系统将无法工作。

## 先审计再部署（建议约 30 天）

1. 在每台 DC 上启用 LDAP 接口诊断以记录未签名的绑定（事件 **2889**）：
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. 将 DC GPO `LDAP server channel binding token requirements` = **When Supported** 以开始 CBT 遥测。
3. 监控 Directory Service 事件：
- **2889** – unsigned/unsigned-allow binds (签名不合规)。
- **3074/3075** – LDAPS binds 将失败或省略 CBT（在 2019/2022 上需要 KB4520412，并且需要上面的步骤 2）。
4. 分开强制执行以下更改：
- `LDAP server channel binding token requirements` = **Always** (DCs)。
- `LDAP client signing requirements` = **Require signing** (clients)。
- `LDAP server signing requirements` = **Require signing** (DCs) **or** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**。

## References

- [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)

{{#include ../../banners/hacktricks-training.md}}
