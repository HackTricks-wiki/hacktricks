# Injection Applications PowerShell w macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` i profile PowerShell

W systemach macOS i Linux PowerShell używa ścieżek konfiguracji XDG i wykonuje skrypty profilu użytkownika podczas uruchamiania `pwsh`. Przekierowanie `XDG_CONFIG_HOME` zmienia katalog zawierający `powershell/profile.ps1` oraz specyficzny dla hosta konsoli `powershell/Microsoft.PowerShell_profile.ps1`; kontrolowany plik w tym miejscu może zatem zostać wykonany przed ładunkiem `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dotyczy to PowerShell 6+ (`pwsh`) na platformach innych niż Windows; Windows PowerShell używa innych lokalizacji profili. `pwsh -NoProfile` pomija ładowanie profili. Sprawdź również `HOME` i nazwy profili specyficzne dla hosta, ponieważ inne hosty PowerShell mogą wybierać inne skrypty.

## References

- [1] [Zmienne środowiskowe PowerShell i ścieżki XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profile PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
