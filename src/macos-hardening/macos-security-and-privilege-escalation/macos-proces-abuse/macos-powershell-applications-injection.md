# Inyección de aplicaciones PowerShell en macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell es multiplataforma: el mismo binario `pwsh` se ejecuta en macOS, Linux y Windows, y es una aplicación **.NET (Core)**. Esto proporciona a un atacante que controla el entorno de una invocación de `pwsh` varias primitivas de ejecución de código mediante variables de entorno que funcionan de forma idéntica en los tres sistemas operativos, además de un par exclusivas de Windows. Todas se ejecutan **antes de** (o en lugar de) `-Command`/`-File` que la víctima pretendía ejecutar, lo que las hace ideales contra wrappers con privilegios, tareas de cron/`launchd`/systemd y runners de CI que ejecutan `pwsh` mediante shell con un entorno heredado.

## `XDG_CONFIG_HOME` y los perfiles de PowerShell

En macOS y Linux, PowerShell utiliza las rutas de configuración de XDG y ejecuta scripts de perfil de usuario cuando se inicia `pwsh`. Redirigir `XDG_CONFIG_HOME` cambia el directorio que contiene `powershell/profile.ps1` y el archivo `powershell/Microsoft.PowerShell_profile.ps1` específico del host de consola; por lo tanto, un archivo controlado ubicado allí puede ejecutarse antes de un payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Esto se aplica a PowerShell 6+ (`pwsh`) en plataformas que no son Windows; Windows PowerShell utiliza ubicaciones de perfiles diferentes. `pwsh -NoProfile` suprime la carga de perfiles. Inspecciona también `HOME` y los nombres de perfil específicos del host, porque otros hosts de PowerShell pueden seleccionar scripts diferentes.

> [!TIP]
> En **Windows**, las rutas de perfil se derivan de `$HOME` / de la carpeta conocida *Documents* (por ejemplo, `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` para `pwsh`, `Documents\WindowsPowerShell\...` para Windows PowerShell), por lo que influir en `HOME`/`USERPROFILE` —o simplemente escribir en ese archivo— es la primitiva equivalente.

## `PSModulePath` module auto-loading hijack

Desde PowerShell 3.0, **module auto-loading** importa automáticamente un módulo la primera vez que se referencia un comando que este exporta (mediante una invocación, `Get-Command` o la finalización con tabulador). PowerShell busca recursivamente en cada directorio incluido en **`$Env:PSModulePath`** archivos `.psd1`/`.psm1`, y en sistemas que no son Windows se respeta tal cual el `PSModulePath` heredado por el proceso. Por lo tanto, si puedes **anteponer un directorio a `PSModulePath`**, puedes colocar un módulo que coincida con un comando que invoque el script de la víctima o con un nombre de módulo que el script ejecute mediante `Import-Module`; así, el código con ámbito de módulo se ejecuta durante la importación.<sup>[[3]](#references)</sup>

Dado que la resolución de comandos de PowerShell sigue el orden *Alias → Function → Cmdlet → Application*, una **función exportada por tu módulo puede ocultar un cmdlet integrado** que utilice el objetivo (por ejemplo, `Get-ChildItem`), por lo que ni siquiera necesitas que la víctima importe algo explícitamente por nombre.
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
En **Windows** se aplica lo mismo (rutas separadas por `;`); `PSModulePath` también obtiene valores de `HKCU:\Environment` y `HKLM:\...\Session Manager\Environment`, por lo que un valor escribible del ámbito del usuario también es una primitive de persistence. La carga automática puede deshabilitarse con `$PSModuleAutoloadingPreference = 'None'`, y `pwsh -NoProfile` **no** la detiene.

## Inyección de CLR profiler (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` se ejecuta en .NET Core, por lo que la **CLR profiling API** carga una DLL/`.so`/`.dylib` del atacante en el proceso durante el inicio únicamente desde el entorno; no se necesita ninguna firma ni registro COM, porque las variables `*_PATH` tienen prioridad sobre el registro. La biblioteca del profiler ejecuta su `DllMain`/punto de entrada dentro del proceso de PowerShell, lo que constituye una técnica clásica de code-execution y persistence in-process (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- En **.NET 8+**, las variables también pueden usar el prefijo más reciente `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` se mantiene por compatibilidad con versiones anteriores.
- En **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), el trío equivalente es **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** y **`COR_PROFILER_PATH=C:\evil.dll`**.

La DLL del profiler solo debe ser una biblioteca COM/ICorProfilerCallback válida (o simplemente realizar su trabajo desde `DllMain`). Los launchers defensivos deben eliminar `COR_*`/`CORECLR_*`/`DOTNET_*` de los entornos privilegiados.

## `DOTNET_STARTUP_HOOKS` (hook de .NET pre-`Main`)

Dado que `pwsh` es una aplicación .NET Core, **`DOTNET_STARTUP_HOOKS`** apunta a un assembly administrado cuyo `StartupHook.Initialize()` se ejecuta de forma síncrona antes del `Main` del host, es decir, antes de que se inicie PowerShell. Esta es la primitiva de managed-code más limpia y se comparte con cualquier otra aplicación .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (bypass de controles de Windows)

En Windows, configurar la variable de entorno **`$Env:PSExecutionPolicyPreference`** (por ejemplo, con `Bypass` o `Unrestricted`) anula la Execution Policy efectiva para ese proceso; esto es exactamente lo que escribe `Set-ExecutionPolicy -Scope Process`. Por sí misma, no ejecuta código, pero elimina la barrera de que "los scripts sin firma están bloqueados", que a menudo es el eslabón que falta para que una de las primitivas anteriores (un profile / module plantado) llegue a ejecutarse. Execution Policy es exclusiva de Windows y nunca fue un límite de seguridad.<sup>[[5]](#references)</sup>

## References

- [1] [Variables de entorno de PowerShell y rutas XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profiles de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath y auto-carga de módulos](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Configuración de debugging y profiling de .NET (variables de profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
