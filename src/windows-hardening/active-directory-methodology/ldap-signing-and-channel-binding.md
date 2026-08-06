# LDAP Signing 与 Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## 为什么重要

LDAP relay/MITM 允许攻击者将 bind 转发到 Domain Controllers，以获取已认证的上下文。两项服务器端控制可以有效阻断这些路径：

- **LDAP Channel Binding (CBT)** 将 LDAPS bind 绑定到特定的 TLS tunnel，阻断跨不同 channel 的 relay/replay。
- **LDAP Signing** 强制使用 integrity-protected LDAP messages，防止篡改并阻断大多数 unsigned relay。

**快速 offensive check**：`netexec ldap <dc> -u user -p pass` 等 tools 会打印服务器状态。如果看到 `(signing:None)` 和 `(channel binding:Never)`，则 Kerberos/NTLM **relays to LDAP** 可行（例如使用 KrbRelayUp 写入 `msDS-AllowedToActOnBehalfOfOtherIdentity` 以实现 RBCD，并 impersonate administrators）。<sup>[[4]](#references)</sup>

**Server 2025 DCs** 引入了新的 GPO（**LDAP server signing requirements Enforcement**）。当该 GPO 保持 **Not Configured** 时，默认设置为 **Require Signing**。若要避免 enforcement，必须明确将该 policy 设置为 **Disabled**。<sup>[[1]](#references)</sup>

## LDAP Channel Binding（仅限 LDAPS）

- **Requirements**：
- CVE-2017-8563 patch（2017）增加了对 Extended Protection for Authentication 的支持。<sup>[[3]](#references)</sup>
- **GPO (DCs)**：`Domain controller: LDAP server channel binding token requirements`
- `Never`（default，不使用 CBT）
- `When Supported`（audit：发出 failures，但不 block）
- `Always`（enforce：拒绝没有 valid CBT 的 LDAPS binds）<sup>[[1]](#references)</sup>
- **Audit**：设置为 **When Supported** 以发现：
- **3074** – 如果启用 enforcement，该 LDAPS bind 将因 CBT validation 失败。
- **3075** – 该 LDAPS bind 未提供 CBT data，如果启用 enforcement 将被拒绝。
- （Event **3039** 仍会在较旧的 builds 上表示 CBT failures。）<sup>[[1]](#references)[[2]](#references)</sup>
- **Enforcement**：确认 LDAPS clients 发送 CBTs 后设置为 **Always**；仅对 **LDAPS** 生效（不适用于 raw 389）。<sup>[[1]](#references)</sup>


## LDAP Signing

- **Client GPO**：`Network security: LDAP client signing requirements` = `Require signing`（而现代 Windows 上的 default 为 `Negotiate signing`）。<sup>[[1]](#references)</sup>
- **DC GPO**：
- Legacy：`Domain controller: LDAP server signing requirements` = `Require signing`（default 为 `None`）。<sup>[[2]](#references)</sup>
- **Server 2025**：将 legacy policy 保持为 `None`，并设置 `LDAP server signing requirements Enforcement` = `Enabled`（Not Configured = 默认 enforced；设置为 `Disabled` 可避免 enforcement）。<sup>[[1]](#references)</sup>
- **Compatibility**：只有 Windows **XP SP3+** 支持 LDAP signing；启用 enforcement 后，较旧的 systems 将无法正常工作。

## Audit-first rollout（建议约 30 天）

1. 在每个 DC 上启用 LDAP interface diagnostics，以记录 unsigned binds（Event **2889**）：<sup>[[1]](#references)</sup>
```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```
2. 将 DC GPO `LDAP server channel binding token requirements` 设置为 **When Supported**，以开始收集 CBT telemetry。<sup>[[1]](#references)</sup>
3. 监控 Directory Service 事件：<sup>[[1]](#references)[[2]](#references)</sup>
- **2889** – unsigned/unsigned-allow binds（不符合 signing 要求）。
- **3074/3075** – 将会失败或省略 CBT 的 LDAPS binds（在 2019/2022 上需要 KB4520412，以及上述第 2 步）。
4. 分别进行以下更改以强制执行：<sup>[[1]](#references)</sup>
- `LDAP server channel binding token requirements` = **Always**（DC）。
- `LDAP client signing requirements` = **Require signing**（客户端）。
- `LDAP server signing requirements` = **Require signing**（DC），**或者**（Server 2025）`LDAP server signing requirements Enforcement` = **Enabled**。

## 参考资料

- [1] [TrustedSec - LDAP Channel Binding and LDAP Signing](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - LDAP channel binding & signing requirements](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - LDAP relay mitigation update](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP signing disabled → Kerberos relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../../banners/hacktricks-training.md}}
