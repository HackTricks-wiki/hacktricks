# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` and PowerShell profiles

On macOS and Linux, PowerShell uses XDG configuration paths and executes user profile scripts when `pwsh` starts. Redirecting `XDG_CONFIG_HOME` changes the directory containing `powershell/profile.ps1` and the console-host-specific `powershell/Microsoft.PowerShell_profile.ps1`; a controlled file there can therefore execute before a `-Command` payload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```

This applies to PowerShell 6+ (`pwsh`) on non-Windows platforms; Windows PowerShell uses different profile locations. `pwsh -NoProfile` suppresses profile loading. Also inspect `HOME` and host-specific profile names because other PowerShell hosts can select different scripts.

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)

{{#include ../../../banners/hacktricks-training.md}}
