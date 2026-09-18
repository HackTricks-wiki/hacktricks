# PowerShell Applications Injection kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell ni cross-platform: binary ya `pwsh` ileile huendeshwa kwenye macOS, Linux na Windows, na ni application ya **.NET (Core)**. Hilo humpa attacker anayesimamia environment ya invocation ya `pwsh` primitives kadhaa za environment-variable → code-execution zinazofanya kazi kwa njia ileile kwenye OS zote tatu, pamoja na nyingine mbili zinazopatikana Windows pekee. Zote hutekelezwa **kabla ya** (au badala ya) `-Command`/`-File` ambayo victim alikusudia kuendesha, jambo linalozifanya zifae dhidi ya wrappers zenye privileges, kazi za cron/`launchd`/systemd na CI runners zinazoendesha `pwsh` kwa kutumia environment iliyorithiwa.

## `XDG_CONFIG_HOME` na PowerShell profiles

Kwenye macOS na Linux, PowerShell hutumia XDG configuration paths na hutekeleza user profile scripts `pwsh` inapoanza. Kuelekeza upya `XDG_CONFIG_HOME` hubadilisha directory iliyo na `powershell/profile.ps1` na `powershell/Microsoft.PowerShell_profile.ps1` maalum kwa console host; kwa hivyo file inayodhibitiwa hapo inaweza kutekelezwa kabla ya `-Command` payload.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Hii inatumika kwa PowerShell 6+ (`pwsh`) kwenye majukwaa yasiyo ya Windows; Windows PowerShell hutumia maeneo tofauti ya profile. `pwsh -NoProfile` huzuia upakiaji wa profile. Pia kagua `HOME` na majina ya profile maalum kwa host, kwa sababu PowerShell hosts nyingine zinaweza kuchagua scripts tofauti.

> [!TIP]
> Kwenye **Windows**, njia za profile hutokana na `$HOME` / folda maalum ya *Documents* (kwa mfano, `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` kwa `pwsh`, `Documents\WindowsPowerShell\...` kwa Windows PowerShell), kwa hiyo kuathiri `HOME`/`USERPROFILE` — au kuandika tu faili hiyo — ni primitive sawa.

## `PSModulePath` module auto-loading hijack

Tangu PowerShell 3.0, **module auto-loading** huingiza module kiotomatiki mara ya kwanza command inayotolewa nayo inapotajwa (inatekelezwa, `Get-Command`, au tab-completion). PowerShell hutafuta kwa kujirudia katika kila directory iliyoorodheshwa kwenye **`$Env:PSModulePath`** kwa faili za `.psd1`/`.psm1`, na kwenye majukwaa yasiyo ya Windows, `PSModulePath` iliyorithiwa na process huheshimiwa jinsi ilivyo. Kwa hiyo, ikiwa unaweza **kuweka directory mbele kwenye `PSModulePath`**, unaweza kupanda module inayolingana na command ambayo victim script inaita au jina la module ambalo script inaingiza kwa `Import-Module` — na code ya kiwango cha module yako itaendeshwa wakati wa kuingizwa.<sup>[[3]](#references)</sup>

Kwa sababu command resolution ya PowerShell ni *Alias → Function → Cmdlet → Application*, **function** iliyotolewa na module yako inaweza kufunika cmdlet iliyojengwa ndani ambayo target inatumia (kwa mfano, `Get-ChildItem`), kwa hiyo huhitaji hata victim kuingiza kitu kwa jina.
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
Kwenye **Windows** hali hiyo hiyo inatumika (`;`-separated paths); `PSModulePath` pia hupokea thamani kutoka `HKCU:\Environment` na `HKLM:\...\Session Manager\Environment`, kwa hivyo thamani ya user-scope inayoweza kuandikwa pia ni primitive ya persistence. Auto-loading inaweza kuzimwa kwa `$PSModuleAutoloadingPreference = 'None'`, na `pwsh -NoProfile` **haisitishe**.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` huendeshwa kwenye .NET Core, kwa hivyo **CLR profiling API** hupakia DLL/`.so`/`.dylib` ya mshambuliaji ndani ya process wakati wa startup kupitia environment pekee — hakuna signature wala COM registration inayohitajika, kwa sababu variables za `*_PATH` zina kipaumbele kuliko registry. `DllMain`/entry point ya profiler library hutekelezwa ndani ya PowerShell process, ambayo ni mbinu ya kawaida ya in-process code-execution na persistence (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Kwenye **.NET 8+**, variables zinaweza pia kutumia prefix mpya ya `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` imehifadhiwa kwa ajili ya backward compatibility.
- Kwenye **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), trio inayolingana ni **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** na **`COR_PROFILER_PATH=C:\evil.dll`**.

Profiler DLL inahitaji tu kuwa library halali ya COM/ICorProfilerCallback (au ifanye kazi yake moja kwa moja kutoka `DllMain`). Defensive launchers zinapaswa kuondoa `COR_*`/`CORECLR_*`/`DOTNET_*` kutoka kwenye mazingira yenye privileges.

## `DOTNET_STARTUP_HOOKS` (pre-`Main` .NET hook)

Kwa kuwa `pwsh` ni application ya .NET Core, **`DOTNET_STARTUP_HOOKS`** inaelekeza kwenye managed assembly ambayo `StartupHook.Initialize()` yake huendeshwa synchronously kabla ya `Main` ya host — yaani, kabla PowerShell yenyewe kuanza. Hii ndiyo primitive safi zaidi ya managed-code na inashirikiwa na kila app nyingine ya .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows control bypass)

Kwenye Windows, kuweka environment variable **`$Env:PSExecutionPolicyPreference`** (kwa mfano kuwa `Bypass` au `Unrestricted`) hubatilisha Execution Policy inayotumika kwa process hiyo — hiki ndicho hasa `Set-ExecutionPolicy -Scope Process` huandika. Hii si code execution yenyewe, lakini huondoa kizuizi cha "unsigned scripts are blocked", ambacho mara nyingi ndicho kiungo kinachokosekana ili mojawapo ya primitives zilizo hapo juu (profile / module iliyopandikizwa) iweze kuendeshwa. Execution Policy ni ya Windows pekee na haijawahi kuwa security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath & module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging & profiling config settings (CORECLR_/DOTNET_ profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
