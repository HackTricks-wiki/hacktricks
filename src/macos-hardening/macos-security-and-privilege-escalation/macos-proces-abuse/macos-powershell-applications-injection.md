# Inyección en aplicaciones de PowerShell de macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` y los perfiles de PowerShell

En macOS y Linux, PowerShell utiliza rutas de configuración XDG y ejecuta scripts de perfil de usuario cuando se inicia `pwsh`. Redirigir `XDG_CONFIG_HOME` cambia el directorio que contiene `powershell/profile.ps1` y el archivo específico del host de consola `powershell/Microsoft.PowerShell_profile.ps1`; por lo tanto, un archivo controlado ubicado allí puede ejecutarse antes de un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Esto se aplica a PowerShell 6+ (`pwsh`) en plataformas que no son Windows; Windows PowerShell utiliza ubicaciones de perfil diferentes. `pwsh -NoProfile` suprime la carga de perfiles. También inspecciona `HOME` y los nombres de perfil específicos del host, ya que otros hosts de PowerShell pueden seleccionar scripts diferentes.

## References

- [1] [Variables de entorno de PowerShell y rutas XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Perfiles de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
