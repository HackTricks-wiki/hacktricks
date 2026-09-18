# macOS PowerShell 应用程序注入

{{#include ../../../banners/hacktricks-training.md}}

PowerShell 是跨平台的：同一个 `pwsh` binary 可在 macOS、Linux 和 Windows 上运行，并且它是一个 **.NET (Core) application**。因此，控制 `pwsh` invocation 环境的攻击者可以利用多个环境变量 → code execution 原语，这些原语在三个操作系统上的行为完全相同，此外还有几个仅适用于 Windows 的原语。所有这些操作都会在受害者原本打算运行的 `-Command`/`-File` 之前（或取而代之）执行，因此非常适合针对特权 wrapper、cron/`launchd`/systemd job，以及通过继承的环境调用 `pwsh` 的 CI runner。

## `XDG_CONFIG_HOME` 和 PowerShell profiles

在 macOS 和 Linux 上，PowerShell 使用 XDG configuration paths，并在 `pwsh` 启动时执行用户 profile scripts。重定向 `XDG_CONFIG_HOME` 会更改包含 `powershell/profile.ps1` 以及特定于 console host 的 `powershell/Microsoft.PowerShell_profile.ps1` 的目录；因此，其中受控的文件可以在 `-Command` payload 之前执行。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
这适用于非 Windows 平台上的 PowerShell 6+（`pwsh`）；Windows PowerShell 使用不同的 profile 路径。`pwsh -NoProfile` 会禁止加载 profile。此外，还应检查 `HOME` 和特定于 host 的 profile 名称，因为其他 PowerShell host 可能会选择不同的脚本。

> [!TIP]
> 在 **Windows** 上，profile 路径源自 `$HOME` / *Documents* known folder（例如，`pwsh` 使用 `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`，Windows PowerShell 使用 `Documents\WindowsPowerShell\...`），因此影响 `HOME`/`USERPROFILE`——或直接写入该文件——就是等效的 primitive。

## `PSModulePath` 模块自动加载劫持

自 PowerShell 3.0 起，**模块自动加载**会在首次引用（调用、`Get-Command` 或 tab-completion）某个模块导出的命令时自动导入该模块。PowerShell 会递归搜索 **`$Env:PSModulePath`** 中列出的每个目录，以查找 `.psd1`/`.psm1` 文件；在非 Windows 平台上，进程继承的 `PSModulePath` 会按原样使用。因此，如果你可以**向 `PSModulePath` 前置添加一个目录**，就可以植入一个模块，使其匹配受害者脚本调用的命令，或脚本 `Import-Module` 的模块名称——并且你的 module-scope 代码会在导入时运行。<sup>[[3]](#references)</sup>

由于 PowerShell 的命令解析顺序是 *Alias → Function → Cmdlet → Application*，你的模块导出的 **function** 可以 shadow 目标使用的内置 cmdlet（例如 `Get-ChildItem`），因此甚至不需要受害者按名称导入任何内容。
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
在 **Windows** 上同样适用（路径以 `;` 分隔）；`PSModulePath` 还会从 `HKCU:\Environment` 和 `HKLM:\...\Session Manager\Environment` 获取值，因此可写的用户范围值同样是一种 persistence primitive。可以通过 `$PSModuleAutoloadingPreference = 'None'` 禁用自动加载，但 `pwsh -NoProfile` **不会**阻止它。

## CLR profiler injection（`CORECLR_PROFILER` / `COR_PROFILER`）

`pwsh` 运行在 .NET Core 上，因此 **CLR profiling API** 会仅凭环境变量在进程启动时将攻击者的 DLL/`.so`/`.dylib` 加载到进程中——无需签名，也无需 COM 注册，因为 `*_PATH` 变量的优先级高于注册表。profiler library 的 `DllMain`/entry point 会在 PowerShell 进程内部执行，这是一种经典的进程内代码执行和 persistence 技术（MITRE ATT&CK **T1574.012**）。<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- 在 **.NET 8+** 上，变量也可以使用较新的 `DOTNET_` 前缀（`DOTNET_EnableDiagnostics=1`、`DOTNET_ENABLE_PROFILING=1`、`DOTNET_PROFILER`、`DOTNET_PROFILER_PATH`）；`CORECLR_*` 为保持向后兼容而保留。
- 在 **Windows PowerShell 5.1**（`powershell.exe`、.NET Framework）上，等效的三个变量是 **`COR_ENABLE_PROFILING=1`**、**`COR_PROFILER={CLSID}`** 和 **`COR_PROFILER_PATH=C:\evil.dll`**。

Profiler DLL 只需是有效的 COM/ICorProfilerCallback library（或者直接从 `DllMain` 执行其操作）。防御性 launcher 应从特权环境中移除 `COR_*`/`CORECLR_*`/`DOTNET_*`。

## `DOTNET_STARTUP_HOOKS`（`Main` 之前的 .NET hook）

由于 `pwsh` 是一个 .NET Core application，**`DOTNET_STARTUP_HOOKS`** 会指向一个 managed assembly，其 `StartupHook.Initialize()` 会在 host 的 `Main` 之前同步运行——也就是说，会在 PowerShell 自身启动之前运行。这是最干净的 managed-code primitive，并且与所有其他 .NET app 共享：

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference`（Windows control bypass）

在 Windows 上，设置环境变量 **`$Env:PSExecutionPolicyPreference`**（例如设置为 `Bypass` 或 `Unrestricted`）会覆盖该进程的有效 Execution Policy——这正是 `Set-ExecutionPolicy -Scope Process` 所写入的内容。它本身不会执行 code，但会移除“阻止 unsigned scripts”的防护措施；这通常是让上述某个 primitive（已植入的 profile / module）实际运行所缺少的关键环节。Execution Policy 仅适用于 Windows，且从未被设计为 security boundary。<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell 环境变量和 XDG 路径](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath 和 module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging 和 profiling 配置设置（CORECLR_/DOTNET_ profiler 变量）](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies（PSExecutionPolicyPreference）](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
