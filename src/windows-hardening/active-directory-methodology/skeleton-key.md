# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** 是一种允许攻击者通过向每个域控制器的 LSASS 进程中**注入主密码**来**绕过 Active Directory 身份验证**的技术。注入后，可以使用主密码（默认值为 **`mimikatz`**）以**任意域用户**的身份进行身份验证，同时这些用户的真实密码仍然有效。<sup>[[1]](#references)[[2]](#references)</sup>

关键事实：

- 需要在每个 DC 上拥有 **Domain Admin/SYSTEM + SeDebugPrivilege**，并且**每次重启后都必须重新应用**。<sup>[[2]](#references)</sup>
- 经典的 Mimikatz 实现会修补 **NTLM** 和 **Kerberos RC4 (etype 0x17)** 验证路径；仅使用 AES 的身份验证不会通过 RC4 hook 接受该 skeleton password。<sup>[[2]](#references)</sup>
- 可能与第三方 LSA authentication packages 或其他 smart-card / MFA providers 发生冲突。<sup>[[2]](#references)</sup>
- Mimikatz module 接受可选开关 `/letaes`，用于避免修改 Kerberos/AES hooks，以应对兼容性问题。<sup>[[3]](#references)</sup>

### 执行

经典的、未受 PPL 保护的 LSASS：
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
如果 **LSASS 以 protected process light (PPL)** 运行，则 user-mode debug access 会被阻止。下面介绍的历史 Mimikatz 操作会加载其 kernel driver，并在 patching LSASS 之前移除保护。Credential Guard 是一种独立的 isolation control，不应与 PPL 混为一谈。<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
注入后，使用任意域账户进行身份验证，但密码使用 `mimikatz`（或 operator 设置的值）。请记住，在多 DC 环境中，必须在 **所有 DC** 上重复此操作。

## 缓解措施

- **日志监控**
- 系统 **Event ID 7045**（服务/驱动安装），用于检测未签名驱动，例如 `mimidrv.sys`。
- **Sysmon**：Event ID 7（驱动加载）用于检测 `mimidrv.sys`；Event ID 10 用于检测来自非系统进程、对 `lsass.exe` 的可疑访问。
- Security **Event ID 4673/4611**，用于检测敏感权限使用或 LSA authentication package 注册异常；将其与来自 DC、使用 RC4（etype 0x17）的异常 4624 登录进行关联。
- **加固 LSASS**
- 在受支持的环境中保持 **RunAsPPL** 和 **Credential Guard** 启用。两者提供不同的保护机制，结合使用可以提高修改或提取 LSASS secrets 的攻击成本，并增加相关 telemetry。<sup>[[4]](#references)</sup>
- 尽可能禁用 legacy **RC4**；仅限于 AES 的 Kerberos tickets 可以阻止 skeleton key 使用的 RC4 hook 路径。<sup>[[2]](#references)</sup>
- 快速 PowerShell 检查：
- 检测未签名 kernel driver 安装：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- 检查 Mimikatz driver：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- 重启后验证 PPL 是否已强制启用：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

如需更多 credential-hardening 指导，请查看 [Windows credentials protections](../stealing-credentials/credentials-protections.md)。

## References

- [1] [Netwrix – Active Directory 中的 Skeleton Key attack（2022）](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key（2026）](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — 配置额外的 LSA 保护](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
