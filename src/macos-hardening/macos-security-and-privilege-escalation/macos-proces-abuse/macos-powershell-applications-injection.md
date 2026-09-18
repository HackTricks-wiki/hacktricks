# Injection d'applications PowerShell sur macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell est cross-platform : le même binaire `pwsh` s’exécute sur macOS, Linux et Windows, et il s’agit d’une application **.NET (Core)**. Cela donne à un attaquant qui contrôle l’environnement d’une invocation de `pwsh` plusieurs primitives variable d’environnement → exécution de code qui fonctionnent de manière identique sur les trois OS, ainsi que quelques primitives spécifiques à Windows. Toutes s’exécutent **avant** (ou à la place de) la commande `-Command`/`-File` que la victime avait l’intention d’exécuter, ce qui les rend idéales contre les wrappers privilégiés, les tâches cron/`launchd`/systemd et les runners CI qui lancent `pwsh` avec un environnement hérité.

## `XDG_CONFIG_HOME` et les profils PowerShell

Sur macOS et Linux, PowerShell utilise les chemins de configuration XDG et exécute les scripts de profil utilisateur au démarrage de `pwsh`. Rediriger `XDG_CONFIG_HOME` modifie le répertoire contenant `powershell/profile.ps1` et le fichier spécifique à l’hôte de console `powershell/Microsoft.PowerShell_profile.ps1` ; un fichier contrôlé à cet emplacement peut donc s’exécuter avant un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Cela s’applique à PowerShell 6+ (`pwsh`) sur les plateformes non-Windows ; Windows PowerShell utilise des emplacements de profil différents. `pwsh -NoProfile` empêche le chargement des profils. Inspectez également `HOME` et les noms de profils spécifiques à l’hôte, car d’autres hôtes PowerShell peuvent sélectionner des scripts différents.

> [!TIP]
> Sous **Windows**, les chemins des profils sont dérivés de `$HOME` / du dossier connu *Documents* (par exemple, `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` pour `pwsh`, `Documents\WindowsPowerShell\...` pour Windows PowerShell). Influencer `HOME`/`USERPROFILE` — ou écrire simplement dans ce fichier — constitue donc la primitive équivalente.

## `PSModulePath` module auto-loading hijack

Depuis PowerShell 3.0, le **module auto-loading** importe automatiquement un module lorsqu’une commande qu’il exporte est référencée pour la première fois (par une invocation, `Get-Command` ou la complétion par tabulation). PowerShell recherche récursivement des fichiers `.psd1`/`.psm1` dans chaque répertoire indiqué par **`$Env:PSModulePath`** et, sur les systèmes non-Windows, la valeur de `PSModulePath` héritée par le processus est respectée telle quelle. Ainsi, si vous pouvez **ajouter un répertoire au début de `PSModulePath`**, vous pouvez déposer un module qui correspond soit à une commande appelée par le script de la victime, soit au nom d’un module que le script exécute avec `Import-Module` — et le code au niveau du module s’exécute lors de l’importation.<sup>[[3]](#references)</sup>

Comme la résolution des commandes PowerShell suit l’ordre *Alias → Function → Cmdlet → Application*, une **fonction exportée par votre module peut masquer un cmdlet intégré** utilisé par la cible (par exemple `Get-ChildItem`) ; la victime n’a donc même pas besoin d’importer explicitement quoi que ce soit par son nom.
```bash
# Attacker-controlled module dir prepended to PSModulePath
mkdir -p /tmp/evil/Hijack
cat >/tmp/evil/Hijack/Hijack.psm1 <<'PS1'
# Top-level module code runs at import time
New-Item -ItemType File -Path /tmp/psmodulepath-executed -Force | Out-Null
function Invoke-Report { 'hijacked' }   # shadows whatever the victim calls
Export-ModuleMember -Function Invoke-Report
PS1
cat >/tmp/evil/Hijack/Hijack.psd1 <<'PS1'
@{ ModuleVersion = '1.0'; RootModule = 'Hijack.psm1'; FunctionsToExport = @('Invoke-Report') }
PS1

# Victim runs pwsh with an inherited/attacker-influenced PSModulePath and calls Invoke-Report
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/psmodulepath-executed && echo 'PSModulePath auto-load executed'
```
Sur **Windows**, le même principe s'applique (chemins séparés par `;`) ; `PSModulePath` récupère également des valeurs depuis `HKCU:\Environment` et `HKLM:\...\Session Manager\Environment`, de sorte qu'une valeur accessible en écriture à l'échelle de l'utilisateur constitue aussi une primitive de persistence. L'auto-chargement peut être désactivé avec `$PSModuleAutoloadingPreference = 'None'`, et `pwsh -NoProfile` ne l'empêche **pas**.

## Injection de profiler CLR (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` s'exécute sur .NET Core ; l'**API de profiling CLR** charge une DLL/`.so`/`.dylib` de l'attaquant dans le processus au démarrage, uniquement à partir de l'environnement — aucune signature ni enregistrement COM n'est nécessaire, car les variables `*_PATH` ont priorité sur le registre. La bibliothèque du profiler exécute son `DllMain`/point d'entrée à l'intérieur du processus PowerShell, ce qui constitue une technique classique d'exécution de code in-process et de persistence (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Sur **.NET 8+**, les variables peuvent également utiliser le préfixe plus récent `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`) ; `CORECLR_*` est conservé pour la rétrocompatibilité.
- Sur **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), le trio équivalent est **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** et **`COR_PROFILER_PATH=C:\evil.dll`**.

La DLL du profiler doit uniquement être une bibliothèque COM/ICorProfilerCallback valide (ou simplement effectuer son travail depuis `DllMain`). Les launchers défensifs doivent supprimer `COR_*`/`CORECLR_*`/`DOTNET_*` des environnements privilégiés.

## `DOTNET_STARTUP_HOOKS` (hook .NET avant `Main`)

Comme `pwsh` est une application .NET Core, **`DOTNET_STARTUP_HOOKS`** pointe vers un assembly managed dont `StartupHook.Initialize()` s'exécute de manière synchrone avant le `Main` de l'hôte — c'est-à-dire avant le démarrage de PowerShell lui-même. Il s'agit de la primitive de code managed la plus propre, partagée avec toutes les autres applications .NET :

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (contournement du contrôle Windows)

Sous Windows, définir la variable d'environnement **`$Env:PSExecutionPolicyPreference`** (par exemple sur `Bypass` ou `Unrestricted`) remplace l'Execution Policy effective pour ce processus — c'est exactement ce que `Set-ExecutionPolicy -Scope Process` écrit. Cela n'exécute pas de code en soi, mais supprime la protection « les scripts non signés sont bloqués », qui est souvent le maillon manquant pour permettre à l'une des primitives ci-dessus (un profile / module implanté) de s'exécuter. L'Execution Policy est propre à Windows et n'a jamais constitué une boundary de sécurité.<sup>[[5]](#references)</sup>

## References

- [1] [Variables d'environnement PowerShell et chemins XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profils PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath et auto-chargement des modules](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Paramètres de configuration du debugging et du profiling .NET (variables de profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
