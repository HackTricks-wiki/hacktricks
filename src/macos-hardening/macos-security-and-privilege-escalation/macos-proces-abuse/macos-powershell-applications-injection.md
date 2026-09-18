# PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell è cross-platform: lo stesso binario `pwsh` viene eseguito su macOS, Linux e Windows, ed è un'applicazione **.NET (Core)**. Questo offre a un attacker che controlla l'ambiente di un'invocazione di `pwsh` diverse primitive di esecuzione di codice tramite variabili d'ambiente → codice, che funzionano allo stesso modo su tutti e tre i sistemi operativi, oltre ad alcune disponibili solo su Windows. Tutte vengono eseguite **prima** (o al posto) di `-Command`/`-File` che la vittima intendeva eseguire, rendendole ideali contro wrapper con privilegi, job di cron/`launchd`/systemd e CI runner che eseguono `pwsh` tramite shell con un ambiente ereditato.

## `XDG_CONFIG_HOME` e profili PowerShell

Su macOS e Linux, PowerShell usa i percorsi di configurazione XDG ed esegue gli script dei profili utente all'avvio di `pwsh`. Il reindirizzamento di `XDG_CONFIG_HOME` modifica la directory contenente `powershell/profile.ps1` e il file specifico del console host `powershell/Microsoft.PowerShell_profile.ps1`; un file controllato in quella posizione può quindi essere eseguito prima di un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Questo si applica a PowerShell 6+ (`pwsh`) su piattaforme non-Windows; Windows PowerShell utilizza percorsi dei profili diversi. `pwsh -NoProfile` impedisce il caricamento dei profili. Controlla anche `HOME` e i nomi dei profili specifici dell'host, perché altri host PowerShell possono selezionare script diversi.

> [!TIP]
> Su **Windows**, i percorsi dei profili derivano da `$HOME` / dalla cartella nota *Documents* (ad esempio `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` per `pwsh`, `Documents\WindowsPowerShell\...` per Windows PowerShell), quindi influenzare `HOME`/`USERPROFILE` — o semplicemente scrivere quel file — costituisce la primitiva equivalente.

## `PSModulePath` module auto-loading hijack

A partire da PowerShell 3.0, il **module auto-loading** importa automaticamente un modulo la prima volta che viene referenziato un comando da esso esportato (tramite esecuzione, `Get-Command` o completamento tramite tabulazione). PowerShell cerca ricorsivamente in ogni directory elencata in **`$Env:PSModulePath`** i file `.psd1`/`.psm1` e, su sistemi non-Windows, il `PSModulePath` ereditato dal processo viene rispettato così com'è. Pertanto, se puoi **anteporre una directory a `PSModulePath`**, puoi installare un modulo che corrisponda a un comando chiamato dallo script della vittima o al nome di un modulo importato dallo script tramite `Import-Module` — e il codice nello scope del modulo viene eseguito al momento dell'importazione.<sup>[[3]](#references)</sup>

Poiché la risoluzione dei comandi di PowerShell segue l'ordine *Alias → Function → Cmdlet → Application*, una **function esportata dal tuo modulo può nascondere un cmdlet integrato** utilizzato dal target (ad esempio `Get-ChildItem`), quindi non è nemmeno necessario che la vittima importi esplicitamente qualcosa tramite il nome.
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
Su **Windows** vale lo stesso principio (percorsi separati da `;`); `PSModulePath` utilizza anche `HKCU:\Environment` e `HKLM:\...\Session Manager\Environment`, quindi un valore scrivibile nell'ambito dell'utente è anch'esso un primitive di persistenza. Il caricamento automatico può essere disabilitato con `$PSModuleAutoloadingPreference = 'None'`, mentre `pwsh -NoProfile` **non** lo impedisce.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` viene eseguito su .NET Core, quindi la **CLR profiling API** carica una DLL/`.so`/`.dylib` dell'attaccante nel processo all'avvio, basandosi esclusivamente sull'ambiente: non è necessaria alcuna firma e non serve la registrazione COM, perché le variabili `*_PATH` hanno la precedenza sul registro. La libreria del profiler esegue il proprio `DllMain`/entry point all'interno del processo PowerShell, una classica tecnica di code execution in-process e persistenza (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Su **.NET 8+** le variabili possono anche utilizzare il nuovo prefisso `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` viene mantenuto per la compatibilità con le versioni precedenti.
- Su **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) la terna equivalente è **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** e **`COR_PROFILER_PATH=C:\evil.dll`**.

La DLL del profiler deve solo essere una libreria COM/ICorProfilerCallback valida (oppure può semplicemente eseguire il proprio lavoro da `DllMain`). I launcher difensivi dovrebbero rimuovere `COR_*`/`CORECLR_*`/`DOTNET_*` dagli ambienti privilegiati.

## `DOTNET_STARTUP_HOOKS` (hook .NET pre-`Main`)

Poiché `pwsh` è un'applicazione .NET Core, **`DOTNET_STARTUP_HOOKS`** punta a un assembly gestito il cui `StartupHook.Initialize()` viene eseguito sincronicamente prima del `Main` dell'host, ovvero prima dell'avvio di PowerShell. Questo è il primitive di managed code più pulito ed è condiviso con ogni altra app .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (bypass dei controlli Windows)

Su Windows, impostare la variabile d'ambiente **`$Env:PSExecutionPolicyPreference`** (ad esempio su `Bypass` o `Unrestricted`) sovrascrive l'Execution Policy effettiva per quel processo: è esattamente ciò che scrive `Set-ExecutionPolicy -Scope Process`. Di per sé non esegue codice, ma rimuove la protezione "gli script non firmati sono bloccati", che spesso è l'anello mancante per fare in modo che una delle primitive precedenti (un profile / modulo piantato) venga effettivamente eseguita. L'Execution Policy è disponibile solo su Windows e non è mai stata una security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [Variabili d'ambiente di PowerShell e percorsi XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profili di PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath e auto-loading dei moduli](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Impostazioni di configurazione per il debugging e il profiling di .NET (variabili profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
