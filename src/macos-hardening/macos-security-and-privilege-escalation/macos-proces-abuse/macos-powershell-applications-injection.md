# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell is cross-platform: dieselfde `pwsh`-binary loop op macOS, Linux en Windows, en dit is ’n **.NET (Core)-toepassing**. Dit gee ’n aanvaller wat die omgewing van ’n `pwsh`-aanroep beheer verskeie omgewingsveranderlike → code execution-primitiewe wat identies op al drie OS’e werk, plus ’n paar wat slegs op Windows werk. Almal voer uit **voor** (of in plaas van) die `-Command`/`-File` wat die slagoffer bedoel het om uit te voer, wat hulle ideaal maak teen bevoorregte wrappers, cron/`launchd`/systemd-take en CI-runners wat `pwsh` met ’n geërfde omgewing aanroep.

## `XDG_CONFIG_HOME` en PowerShell-profiele

Op macOS en Linux gebruik PowerShell XDG-konfigurasiepaaie en voer dit gebruikersprofielskripte uit wanneer `pwsh` begin. Deur `XDG_CONFIG_HOME` te herlei, verander die gids wat `powershell/profile.ps1` en die konsole-gasheer-spesifieke `powershell/Microsoft.PowerShell_profile.ps1` bevat; ’n beheerde lêer daar kan dus voor ’n `-Command`-payload uitvoer.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dit is van toepassing op PowerShell 6+ (`pwsh`) op nie-Windows-platforms; Windows PowerShell gebruik ander profile-liggings. `pwsh -NoProfile` onderdruk die laai van profiles. Inspekteer ook `HOME` en gasheer-spesifieke profielname, omdat ander PowerShell-hosts verskillende scripts kan kies.

> [!TIP]
> Op **Windows** word die profile-paaie afgelei van `$HOME` / die bekende *Documents*-lêergids (byvoorbeeld `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` vir `pwsh`, `Documents\WindowsPowerShell\...` vir Windows PowerShell), dus is die beïnvloeding van `HOME`/`USERPROFILE` — of die eenvoudige skryf van daardie lêer — die ekwivalente primitief.

## `PSModulePath` module auto-loading hijack

Sedert PowerShell 3.0 voer **module auto-loading** ’n module outomaties in die eerste keer wanneer daar na ’n opdrag wat dit uitvoer, verwys word (dit word uitgevoer, met `Get-Command` opgehaal, of deur tab-completion aangevra). PowerShell soek rekursief in elke gids wat in **`$Env:PSModulePath`** gelys is vir `.psd1`/`.psm1`-lêers, en op nie-Windows word die proses-geërfde `PSModulePath` onveranderd eerbiedig. As jy dus **’n gids vooraan `PSModulePath` kan plaas**, kan jy ’n module plant wat óf ooreenstem met ’n opdrag wat die slagoffer se script aanroep, óf met ’n modulenaam wat die script met `Import-Module` invoer — en jou module-scope-kode loop tydens invoer.<sup>[[3]](#references)</sup>

Omdat PowerShell-opdragresolusie *Alias → Function → Cmdlet → Application* is, kan ’n **function wat deur jou module uitgevoer word, ’n ingeboude cmdlet oorskadu** wat die teiken gebruik (byvoorbeeld `Get-ChildItem`), sodat jy nie eens nodig het dat die slagoffer enigiets volgens naam invoer nie.
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
Op **Windows** geld dieselfde (`;`-geskeide paths); `PSModulePath` word ook gevoed deur `HKCU:\Environment` en `HKLM:\...\Session Manager\Environment`, dus is ’n skryfbare user-scope-waarde ook ’n persistence primitive. Auto-loading kan gedeaktiveer word met `$PSModuleAutoloadingPreference = 'None'`, en `pwsh -NoProfile` keer dit **nie** nie.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` loop op .NET Core, dus laai die **CLR profiling API** ’n aanvaller se DLL/`.so`/`.dylib` in die proses tydens opstart, uitsluitlik vanuit die environment — geen signature of COM-registrasie word benodig nie, omdat die `*_PATH`-veranderlikes voorkeur bo die registry geniet. Die profiler library se `DllMain`/entry point word binne die PowerShell-proses uitgevoer, wat ’n klassieke in-process code-execution- en persistence-tegniek is (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Op **.NET 8+** kan die veranderlikes ook die nuwer `DOTNET_`-voorvoegsel gebruik (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` word vir terugwaartse verenigbaarheid behou.
- Op **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) is die ekwivalente trio **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** en **`COR_PROFILER_PATH=C:\evil.dll`**.

Die profiler DLL hoef slegs 'n geldige COM/ICorProfilerCallback-biblioteek te wees (of eenvoudig sy werk vanuit `DllMain` te doen). Defensive launchers behoort `COR_*`/`CORECLR_*`/`DOTNET_*` uit bevoorregte omgewings te verwyder.

## `DOTNET_STARTUP_HOOKS` (.NET-hook voor `Main`)

Omdat `pwsh` 'n .NET Core-toepassing is, wys **`DOTNET_STARTUP_HOOKS`** na 'n managed assembly waarvan `StartupHook.Initialize()` sinchronies uitgevoer word voordat die host se `Main` loop — dit wil sê voordat PowerShell self begin. Dit is die skoonste managed-code primitive en word met elke ander .NET-toepassing gedeel:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows-beheeromseiling)

Op Windows ignoreer die instelling van die omgewingsveranderlike **`$Env:PSExecutionPolicyPreference`** (byvoorbeeld na `Bypass` of `Unrestricted`) die effektiewe Execution Policy vir daardie proses — dit is presies wat `Set-ExecutionPolicy -Scope Process` skryf. Dit is nie op sigself code execution nie, maar dit verwyder die "unsigned scripts are blocked"-beskermingsmaatreël, wat dikwels die ontbrekende skakel is om een van die primitives hierbo (a planted profile / module) werklik te laat loop. Execution Policy is slegs vir Windows en was nooit 'n security boundary nie.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables and XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath & module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging & profiling config settings (CORECLR_/DOTNET_ profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
