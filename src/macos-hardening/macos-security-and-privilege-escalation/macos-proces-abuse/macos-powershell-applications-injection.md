# Uingizaji wa Applications za PowerShell kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` na profiles za PowerShell

Kwenye macOS na Linux, PowerShell hutumia njia za usanidi za XDG na huendesha scripts za profile za mtumiaji wakati `pwsh` inapoanza. Kuelekeza upya `XDG_CONFIG_HOME` hubadilisha directory iliyo na `powershell/profile.ps1` na `powershell/Microsoft.PowerShell_profile.ps1` maalum kwa console host; kwa hivyo, file inayodhibitiwa iliyowekwa hapo inaweza kutekelezwa kabla ya payload ya `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Hii inatumika kwa PowerShell 6+ (`pwsh`) kwenye platforms zisizo za Windows; Windows PowerShell hutumia maeneo tofauti ya wasifu. `pwsh -NoProfile` huzuia upakiaji wa wasifu. Pia kagua `HOME` na majina ya wasifu mahususi kwa host kwa sababu PowerShell hosts nyingine zinaweza kuchagua scripts tofauti.

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Wasifu wa PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
