# Ubrizgavanje u macOS PowerShell aplikacije

{{#include ../../../banners/hacktricks-training.md}}

PowerShell je cross-platform: isti `pwsh` binarni fajl radi na macOS-u, Linux-u i Windows-u, a u pitanju je **.NET (Core) aplikacija**. To napadaču koji kontroliše okruženje `pwsh` poziva pruža nekoliko primitiva za izvršavanje koda putem promenljivih okruženja, koji rade identično na sva tri OS-a, kao i nekoliko primitiva dostupnih samo na Windows-u. Svi se izvršavaju **pre** komande `-Command`/`-File` koju je žrtva nameravala da pokrene (ili umesto nje), što ih čini idealnim za napade na privilegovane wrapper-e, cron/`launchd`/systemd poslove i CI runners koji pozivaju `pwsh` sa nasleđenim okruženjem.

## `XDG_CONFIG_HOME` i PowerShell profili

Na macOS-u i Linux-u, PowerShell koristi XDG konfiguracione putanje i izvršava korisničke profile kada se `pwsh` pokrene. Preusmeravanje promenljive `XDG_CONFIG_HOME` menja direktorijum koji sadrži `powershell/profile.ps1` i `powershell/Microsoft.PowerShell_profile.ps1`, specifičan za console host; kontrolisana datoteka na toj lokaciji stoga može da se izvrši pre `-Command` payload-a.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Ovo se odnosi na PowerShell 6+ (`pwsh`) na platformama koje nisu Windows; Windows PowerShell koristi drugačije lokacije profila. `pwsh -NoProfile` onemogućava učitavanje profila. Takođe proverite `HOME` i nazive profila specifične za host, jer drugi PowerShell hostovi mogu izabrati drugačije skripte.

> [!TIP]
> Na **Windowsu** putanje profila izvode se iz poznate fascikle `$HOME` / *Documents* (npr. `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` za `pwsh`, `Documents\WindowsPowerShell\...` za Windows PowerShell), pa je uticanje na `HOME`/`USERPROFILE` — ili jednostavno upisivanje u tu datoteku — ekvivalentna primitiva.

## Hijacking automatskog učitavanja modula `PSModulePath`

Od PowerShell-a 3.0, **automatsko učitavanje modula** automatski uvozi modul kada se prvi put referencira komanda koju on izvozi (pozivom, pomoću `Get-Command` ili dovršavanjem naredbi pomoću tastera Tab). PowerShell rekurzivno pretražuje svaki direktorijum naveden u **`$Env:PSModulePath`** u potrazi za datotekama `.psd1`/`.psm1`, a na platformama koje nisu Windows uvažava `PSModulePath` nasleđen od procesa bez izmena. Dakle, ako možete da **dodate direktorijum na početak `PSModulePath`**, možete postaviti modul koji se ili poklapa sa komandom koju skripta žrtve poziva ili sa nazivom modula koji skripta učitava pomoću `Import-Module` — a kod na nivou modula izvršava se u trenutku uvoza.<sup>[[3]](#references)</sup>

Pošto je rezolucija PowerShell komandi po redosledu *Alias → Function → Cmdlet → Application*, **funkcija koju vaš modul izvozi može zaseniti ugrađeni cmdlet** koji cilj koristi (npr. `Get-ChildItem`), tako da žrtva čak ne mora ništa da uvozi po imenu.
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
Na **Windows** važi isto (`;`-razdvojene putanje); `PSModulePath` takođe preuzima vrednosti iz `HKCU:\Environment` i `HKLM:\...\Session Manager\Environment`, pa je upisiva vrednost u opsegu korisnika takođe primitiv za persistence. Automatsko učitavanje može da se onemogući pomoću `$PSModuleAutoloadingPreference = 'None'`, a `pwsh -NoProfile` ga **ne** zaustavlja.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` radi na .NET Core-u, tako da **CLR profiling API** učitava napadačev DLL/`.so`/`.dylib` u proces pri pokretanju isključivo na osnovu environment-a — bez potpisa i bez potrebe za COM registracijom, jer promenljive `*_PATH` imaju prednost nad registry-jem. `DllMain`/entry point profiler biblioteke izvršava se unutar PowerShell procesa, što predstavlja klasičnu tehniku code execution-a unutar procesa i persistence-a (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Na **.NET 8+** promenljive mogu koristiti i noviji prefiks `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` se zadržava zbog kompatibilnosti sa starijim verzijama.
- Na **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework), odgovarajuća trojka je **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** i **`COR_PROFILER_PATH=C:\evil.dll`**.

Profiler DLL samo treba da bude validna COM/ICorProfilerCallback biblioteka (ili da jednostavno obavlja svoj posao iz `DllMain`). Defanzivni launcher-i treba da uklone `COR_*`/`CORECLR_*`/`DOTNET_*` iz privilegovanih okruženja.

## `DOTNET_STARTUP_HOOKS` (.NET hook pre `Main`)

Pošto je `pwsh` .NET Core aplikacija, **`DOTNET_STARTUP_HOOKS`** pokazuje na managed assembly čiji se `StartupHook.Initialize()` sinhrono izvršava pre `Main` host-a — odnosno pre nego što se sam PowerShell pokrene. Ovo je najčistiji primitive za managed code i zajednički je za sve druge .NET aplikacije:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (zaobilaženje Windows kontrole)

Na Windows-u, postavljanje promenljive okruženja **`$Env:PSExecutionPolicyPreference`** (npr. na `Bypass` ili `Unrestricted`) zamenjuje važeću Execution Policy za taj proces — upravo to upisuje `Set-ExecutionPolicy -Scope Process`. Samo po sebi ne izvršava code, ali uklanja zaštitnu meru „unsigned scripts are blocked“, što je često karika koja nedostaje da bi se jedan od prethodnih primitives (postavljen profile / module) zaista pokrenuo. Execution Policy postoji samo na Windows-u i nikada nije predstavljala bezbednosnu granicu.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell promenljive okruženja i XDG putanje](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profili](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath i automatsko učitavanje modula](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Podešavanja za .NET debugging i profiling (CORECLR_/DOTNET_ profiler promenljive)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
