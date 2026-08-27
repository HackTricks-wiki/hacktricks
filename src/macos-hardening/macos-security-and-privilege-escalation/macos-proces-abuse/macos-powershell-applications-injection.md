# macOS PowerShell-toepassingsinspuiting

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` en PowerShell-profiele

Op macOS en Linux gebruik PowerShell XDG-konfigurasiepaaie en voer dit gebruikersprofielskripte uit wanneer `pwsh` begin. Deur `XDG_CONFIG_HOME` te herlei, verander die gids wat `powershell/profile.ps1` en die konsole-gasheer-spesifieke `powershell/Microsoft.PowerShell_profile.ps1` bevat; ’n beheerde lêer daar kan dus uitvoer voordat ’n `-Command`-payload uitgevoer word.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dit is van toepassing op PowerShell 6+ (`pwsh`) op nie-Windows-platforms; Windows PowerShell gebruik ander profielliggings. `pwsh -NoProfile` onderdruk die laai van profiele. Ondersoek ook `HOME` en gasheerspesifieke profielname, omdat ander PowerShell-hosts verskillende scripts kan kies.

## References

- [1] [PowerShell-omgewingsveranderlikes en XDG-paaie](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell-profiele](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
