# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell은 cross-platform입니다. 동일한 `pwsh` binary가 macOS, Linux 및 Windows에서 실행되며 **.NET (Core) application**입니다. 따라서 `pwsh` invocation의 environment를 제어할 수 있는 attacker는 세 OS 모두에서 동일하게 작동하는 여러 environment-variable → code-execution primitive와 Windows 전용 primitive 두 가지를 활용할 수 있습니다. 이 모든 primitive는 victim이 실행하려던 `-Command`/`-File`보다 **먼저** (또는 그 대신) 실행되므로, inherited environment를 사용해 `pwsh`를 호출하는 privileged wrapper, cron/`launchd`/systemd job 및 CI runner를 대상으로 하기에 적합합니다.

## `XDG_CONFIG_HOME` 및 PowerShell profiles

macOS와 Linux에서 PowerShell은 XDG configuration path를 사용하고 `pwsh`가 시작될 때 user profile script를 실행합니다. `XDG_CONFIG_HOME`을 redirect하면 `powershell/profile.ps1` 및 console-host-specific `powershell/Microsoft.PowerShell_profile.ps1`이 포함된 directory가 변경됩니다. 따라서 해당 위치에 제어 가능한 file을 두면 `-Command` payload보다 먼저 실행할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
이는 Windows 이외의 플랫폼에서 PowerShell 6+(`pwsh`)에 적용되며, Windows PowerShell은 다른 profile 위치를 사용합니다. `pwsh -NoProfile`은 profile 로딩을 억제합니다. 또한 다른 PowerShell host가 서로 다른 script를 선택할 수 있으므로 `HOME`과 host별 profile 이름도 확인해야 합니다.

> [!TIP]
> **Windows**에서는 profile 경로가 `$HOME` / *Documents* known folder에서 파생됩니다(예: `pwsh`의 경우 `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`, Windows PowerShell의 경우 `Documents\WindowsPowerShell\...`). 따라서 `HOME`/`USERPROFILE`에 영향을 주거나 해당 파일을 직접 작성하는 것이 동일한 primitive입니다.

## `PSModulePath` module auto-loading hijack

PowerShell 3.0부터 **module auto-loading**은 module이 export하는 command가 처음으로 참조될 때(실행, `Get-Command` 또는 tab-completion) 해당 module을 자동으로 import합니다. PowerShell은 **`$Env:PSModulePath`**에 나열된 모든 directory를 재귀적으로 검색하여 `.psd1`/`.psm1` 파일을 찾으며, Windows 이외의 환경에서는 process가 상속한 `PSModulePath`가 있는 그대로 적용됩니다. 따라서 **`PSModulePath`에 directory를 앞에 추가**할 수 있다면, 대상 script가 호출하는 command 또는 script가 `Import-Module`하는 module 이름과 일치하는 module을 심을 수 있으며, import 시점에 해당 module-scope code가 실행됩니다.<sup>[[3]](#references)</sup>

PowerShell command resolution은 *Alias → Function → Cmdlet → Application* 순서이므로, **module이 export하는 function은 대상이 사용하는 built-in cmdlet**(예: `Get-ChildItem`)을 shadow할 수 있습니다. 따라서 victim이 이름으로 무언가를 import하도록 할 필요조차 없습니다.
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
**Windows**에서도 동일하게 적용됩니다(`;`로 구분된 paths). `PSModulePath`는 `HKCU:\Environment` 및 `HKLM:\...\Session Manager\Environment`에서도 값을 가져오므로, 쓰기 가능한 사용자 범위 값 역시 persistence primitive입니다. `$PSModuleAutoloadingPreference = 'None'`으로 auto-loading을 비활성화할 수 있지만, `pwsh -NoProfile`은 이를 차단하지 않습니다.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh`는 .NET Core에서 실행되므로, **CLR profiling API**는 시작 시 환경 변수만으로 attacker DLL/`.so`/`.dylib`을 process에 로드합니다. signature가 필요하지 않으며, `*_PATH` 변수가 registry보다 우선하므로 COM registration도 필요하지 않습니다. profiler library의 `DllMain`/entry point는 PowerShell process 내부에서 실행되며, 이는 전형적인 in-process code-execution 및 persistence technique입니다(MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- **.NET 8+**에서는 변수가 더 새로운 `DOTNET_` prefix도 사용할 수 있습니다(`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`). `CORECLR_*`는 backwards compatibility를 위해 유지됩니다.
- **Windows PowerShell 5.1**(`powershell.exe`, .NET Framework)에서는 이에 대응하는 trio가 **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`**, **`COR_PROFILER_PATH=C:\evil.dll`**입니다.

profiler DLL은 유효한 COM/ICorProfilerCallback library이기만 하면 되며(`DllMain`에서 직접 작업을 수행해도 됨), Defensive launcher는 privileged environment에서 `COR_*`/`CORECLR_*`/`DOTNET_*`를 제거해야 합니다.

## `DOTNET_STARTUP_HOOKS` (pre-`Main` .NET hook)

`pwsh`는 .NET Core application이므로 **`DOTNET_STARTUP_HOOKS`**는 managed assembly를 가리키며, 해당 assembly의 `StartupHook.Initialize()`는 host의 `Main` 전에, 즉 PowerShell 자체가 시작되기 전에 synchronously 실행됩니다. 이는 가장 깔끔한 managed-code primitive이며 다른 모든 .NET app에서도 공유됩니다.

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows control bypass)

Windows에서 environment variable **`$Env:PSExecutionPolicyPreference`**를 설정하면(예: `Bypass` 또는 `Unrestricted`) 해당 process에 적용되는 Execution Policy를 override합니다. 이는 정확히 `Set-ExecutionPolicy -Scope Process`가 기록하는 값입니다. 그 자체로 code execution을 수행하는 것은 아니지만, "unsigned scripts are blocked"라는 guardrail을 제거합니다. 이는 위 primitive 중 하나(예: planted profile / module)가 실제로 실행되도록 만드는 데 자주 필요한 missing link입니다. Execution Policy는 Windows 전용이며 security boundary였던 적이 없습니다.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath & module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging & profiling config settings (CORECLR_/DOTNET_ profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
