# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key 攻击**是一种复杂的技术，允许攻击者通过**将主密码注入域控制器**来**绕过 Active Directory 认证**。这使得攻击者能够**以任何用户的身份进行认证**而无需他们的密码，从而**授予他们对域的无限制访问**。

可以使用 [Mimikatz](https://github.com/gentilkiwi/mimikatz) 执行此攻击。进行此攻击的**前提是拥有域管理员权限**，攻击者必须针对每个域控制器以确保全面的突破。然而，攻击的效果是暂时的，因为**重启域控制器会消除恶意软件**，需要重新实施以维持访问。

**执行攻击**只需一个命令：`misc::skeleton`。

## Mitigations

针对此类攻击的缓解策略包括监控特定事件 ID，以指示服务的安装或敏感权限的使用。具体来说，查找系统事件 ID 7045 或安全事件 ID 4673 可以揭示可疑活动。此外，将 `lsass.exe` 作为受保护的进程运行可以显著阻碍攻击者的努力，因为这要求他们使用内核模式驱动程序，从而增加攻击的复杂性。

以下是增强安全措施的 PowerShell 命令：

- 要检测可疑服务的安装，请使用：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`

- 特别是，要检测 Mimikatz 的驱动程序，可以使用以下命令：`Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`

- 为了加强 `lsass.exe`，建议将其启用为受保护的进程：`New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`

在系统重启后进行验证至关重要，以确保保护措施已成功应用。这可以通过以下命令实现：`Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*`

## References

- [https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)

{{#include ../../banners/hacktricks-training.md}}
