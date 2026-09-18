# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell は cross-platform です。同じ `pwsh` バイナリが macOS、Linux、Windows で動作し、**.NET (Core) application** でもあります。そのため、`pwsh` の invocation の環境を制御できる攻撃者は、3 つすべての OS で同じように機能する、いくつかの environment variable → code execution primitive と、Windows 専用のものを 2 つ利用できます。これらはすべて、被害者が実行するつもりだった `-Command`/`-File` より**前に**（またはその**代わりに**）実行されるため、継承された環境を使用して `pwsh` を呼び出す privileged wrapper、cron/`launchd`/systemd job、CI runner に対して特に有効です。

## `XDG_CONFIG_HOME` and PowerShell profiles

macOS と Linux では、PowerShell は XDG configuration path を使用し、`pwsh` の起動時に user profile script を実行します。`XDG_CONFIG_HOME` をリダイレクトすると、`powershell/profile.ps1` と console-host-specific な `powershell/Microsoft.PowerShell_profile.ps1` が含まれるディレクトリが変更されます。そのため、そこに配置した制御可能なファイルによって、`-Command` payload より前に code execution を実行できます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
これは、Windows 以外のプラットフォーム上の PowerShell 6 以降（`pwsh`）に適用されます。Windows PowerShell は異なる profile の場所を使用します。`pwsh -NoProfile` は profile の読み込みを抑制します。また、他の PowerShell host が異なる script を選択する可能性があるため、`HOME` と host 固有の profile 名も確認してください。

> [!TIP]
> **Windows** では、profile のパスは `$HOME` / *Documents* known folder から派生します（例：`pwsh` の場合は `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`、Windows PowerShell の場合は `Documents\WindowsPowerShell\...`）。そのため、`HOME`/`USERPROFILE` に影響を与えること、または単にその file に書き込むことが同等の primitive になります。

## `PSModulePath` module auto-loading hijack

PowerShell 3.0 以降、**module auto-loading** は、module が export する command が初めて参照された時（invoke、`Get-Command`、または tab-completion）に、その module を自動的に import します。PowerShell は **`$Env:PSModulePath`** に列挙されたすべての directory を再帰的に検索し、`.psd1`/`.psm1` file を探します。また、Windows 以外では、process から継承された `PSModulePath` がそのまま使用されます。したがって、**`PSModulePath` に directory を prepend** できれば、victim script が呼び出す command、または script が `Import-Module` する module name に一致する module を配置でき、その module-scope code は import 時に実行されます。<sup>[[3]](#references)</sup>

PowerShell の command resolution は *Alias → Function → Cmdlet → Application* の順で行われるため、target が使用する built-in cmdlet（例：`Get-ChildItem`）を、あなたの module が export する **function** で shadow できます。つまり、victim が名前を指定して何かを import する必要さえありません。
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
**Windows**でも同様です（`;`区切りのパス）。`PSModulePath`は`HKCU:\Environment`および`HKLM:\...\Session Manager\Environment`からも値を取得するため、書き込み可能なユーザースコープの値も永続化のプリミティブになります。自動ロードは`$PSModuleAutoloadingPreference = 'None'`で無効化できますが、`pwsh -NoProfile`では無効化されません。

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh`は.NET Core上で動作するため、**CLR profiling API**は環境変数だけを使用して、起動時に攻撃者のDLL/`.so`/`.dylib`をプロセスへロードできます。署名は不要で、`*_PATH`変数がレジストリより優先されるため、COM registrationも必要ありません。プロファイラーライブラリの`DllMain`/エントリポイントはPowerShellプロセス内で実行されます。これは、プロセス内コード実行および永続化の典型的な手法です（MITRE ATT&CK **T1574.012**）。<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- **.NET 8+** では、変数に新しい `DOTNET_` prefix（`DOTNET_EnableDiagnostics=1`、`DOTNET_ENABLE_PROFILING=1`、`DOTNET_PROFILER`、`DOTNET_PROFILER_PATH`）も使用できます。`CORECLR_*` は backward compatibility のために維持されています。
- **Windows PowerShell 5.1**（`powershell.exe`、.NET Framework）では、対応する3つの変数は **`COR_ENABLE_PROFILING=1`**、**`COR_PROFILER={CLSID}`**、**`COR_PROFILER_PATH=C:\evil.dll`** です。

profiler DLL は、有効な COM/ICorProfilerCallback library（または単に `DllMain` から処理を実行するもの）である必要があります。Defensive launcher は、privileged environment から `COR_*`/`CORECLR_*`/`DOTNET_*` を削除する必要があります。

## `DOTNET_STARTUP_HOOKS`（`Main` 前の .NET hook）

`pwsh` は .NET Core application であるため、**`DOTNET_STARTUP_HOOKS`** は、host の `Main` より前、つまり PowerShell 自体の開始前に、`StartupHook.Initialize()` が同期的に実行される managed assembly を指定します。これは最もクリーンな managed-code primitive であり、他のすべての .NET app と共有されます。

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference`（Windows control bypass）

Windows では、environment variable **`$Env:PSExecutionPolicyPreference`**（例: `Bypass` または `Unrestricted`）を設定すると、その process に対する有効な Execution Policy が override されます。これは `Set-ExecutionPolicy -Scope Process` が書き込む内容とまったく同じです。これ自体は code execution ではありませんが、「unsigned scripts are blocked」という guardrail を削除します。これは、上記の primitive のいずれか（planted profile / module）を実際に実行させるために欠けていることが多い要素です。Execution Policy は Windows 専用であり、セキュリティ境界として機能したことはありません。<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables と XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath と module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging と profiling config settings（CORECLR_/DOTNET_ profiler variables）](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies（PSExecutionPolicyPreference）](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
