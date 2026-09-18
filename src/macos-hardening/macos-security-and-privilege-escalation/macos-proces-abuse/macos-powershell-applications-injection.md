# Injection Applications PowerShell w macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell jest wieloplatformowy: ten sam binarny plik `pwsh` działa w systemach macOS, Linux i Windows, a ponadto jest aplikacją **.NET (Core)**. Daje to atakującemu, który kontroluje środowisko wywołania `pwsh`, kilka mechanizmów wykonywania kodu opartych na zmiennych środowiskowych, działających identycznie we wszystkich trzech systemach operacyjnych, a także kilka mechanizmów dostępnych wyłącznie w Windows. Wszystkie wykonują się **przed** (lub zamiast) opcji `-Command`/`-File`, którą ofiara zamierzała uruchomić, co czyni je idealnymi przeciwko uprzywilejowanym wrapperom, zadaniom cron/`launchd`/systemd oraz runnerom CI, które uruchamiają `pwsh` z odziedziczonym środowiskiem.

## `XDG_CONFIG_HOME` i profile PowerShell

W systemach macOS i Linux PowerShell używa ścieżek konfiguracyjnych XDG i wykonuje skrypty profili użytkownika podczas uruchamiania `pwsh`. Przekierowanie `XDG_CONFIG_HOME` zmienia katalog zawierający `powershell/profile.ps1` oraz specyficzny dla hosta konsoli plik `powershell/Microsoft.PowerShell_profile.ps1`; kontrolowany plik w tym miejscu może więc wykonać się przed payloadem `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dotyczy to PowerShell 6+ (`pwsh`) na platformach innych niż Windows; Windows PowerShell używa innych lokalizacji profili. `pwsh -NoProfile` wyłącza ładowanie profilu. Sprawdź również `HOME` i nazwy profili specyficzne dla hosta, ponieważ inne hosty PowerShell mogą wybierać inne skrypty.

> [!TIP]
> W systemie **Windows** ścieżki profili są wyprowadzane z `$HOME` / znanego folderu *Documents* (np. `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` dla `pwsh`, `Documents\WindowsPowerShell\...` dla Windows PowerShell), więc modyfikowanie `HOME`/`USERPROFILE` — lub po prostu zapisanie tego pliku — jest równoważnym prymitywem.

## Przejęcie automatycznego ładowania modułów `PSModulePath`

Od PowerShell 3.0 **automatyczne ładowanie modułów** importuje moduł automatycznie przy pierwszym odwołaniu do eksportowanego przez niego polecenia (wywołaniu, `Get-Command` lub uzupełnianiu za pomocą tabulatora). PowerShell rekurencyjnie przeszukuje każdy katalog wymieniony w **`$Env:PSModulePath`** pod kątem plików `.psd1`/`.psm1`, a na platformach innych niż Windows wartość `PSModulePath` odziedziczona przez proces jest respektowana bez zmian. Jeśli możesz **dodać katalog na początku `PSModulePath`**, możesz umieścić moduł, który pasuje do polecenia wywoływanego przez skrypt ofiary lub do nazwy modułu importowanego przez skrypt za pomocą `Import-Module` — kod w zakresie modułu zostanie wykonany podczas importu.<sup>[[3]](#references)</sup>

Ponieważ rozwiązywanie poleceń w PowerShell odbywa się w kolejności *Alias → Function → Cmdlet → Application*, **funkcja wyeksportowana przez Twój moduł może przesłonić wbudowany cmdlet**, którego używa cel (np. `Get-ChildItem`), więc ofiara nie musi nawet importować czegokolwiek po nazwie.
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
W przypadku **Windows** obowiązuje to samo (`;`-rozdzielane ścieżki); `PSModulePath` pobiera również wartości z `HKCU:\Environment` oraz `HKLM:\...\Session Manager\Environment`, więc zapisywalna wartość w zakresie użytkownika jest także prymitywem persistence. Auto-loading można wyłączyć za pomocą `$PSModuleAutoloadingPreference = 'None'`, a `pwsh -NoProfile` **nie** zatrzymuje tego mechanizmu.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` działa na platformie .NET Core, więc **CLR profiling API** ładuje DLL/`.so`/`.dylib` atakującego do procesu podczas uruchamiania wyłącznie na podstawie zmiennych środowiskowych — bez podpisu i bez konieczności rejestracji COM, ponieważ zmienne `*_PATH` mają pierwszeństwo przed rejestrem. Biblioteka profilera wykonuje `DllMain`/entry point wewnątrz procesu PowerShell, co stanowi klasyczną technikę in-process code-execution i persistence (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- W **.NET 8+** zmienne mogą również używać nowszego prefiksu `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` jest zachowany w celu zapewnienia wstecznej kompatybilności.
- W **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) odpowiednikiem jest zestaw **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** oraz **`COR_PROFILER_PATH=C:\evil.dll`**.

DLL profilu musi być jedynie prawidłową biblioteką COM/ICorProfilerCallback (lub może po prostu wykonywać swoje działania z poziomu `DllMain`). Mechanizmy uruchamiające w sposób defensywny powinny usuwać `COR_*`/`CORECLR_*`/`DOTNET_*` z uprzywilejowanych środowisk.

## `DOTNET_STARTUP_HOOKS` (hook .NET przed `Main`)

Ponieważ `pwsh` jest aplikacją .NET Core, **`DOTNET_STARTUP_HOOKS`** wskazuje zarządzany assembly, którego `StartupHook.Initialize()` jest wykonywane synchronicznie przed `Main` hosta — czyli zanim uruchomi się sam PowerShell. Jest to najczystszy primitive dla managed code i jest współdzielony ze wszystkimi innymi aplikacjami .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (obejście kontroli w Windows)

W Windows ustawienie zmiennej środowiskowej **`$Env:PSExecutionPolicyPreference`** (np. na `Bypass` lub `Unrestricted`) zastępuje efektywną Execution Policy dla tego procesu — dokładnie to zapisuje `Set-ExecutionPolicy -Scope Process`. Samo w sobie nie wykonuje kodu, ale usuwa zabezpieczenie „unsigned scripts are blocked”, które często stanowi brakujące ogniwo umożliwiające faktyczne uruchomienie jednego z powyższych primitives (podłożonego profilu / modułu). Execution Policy jest dostępne wyłącznie w Windows i nigdy nie stanowiło granicy bezpieczeństwa.<sup>[[5]](#references)</sup>

## References

- [1] [Zmienne środowiskowe PowerShell i ścieżki XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Profile PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath i automatyczne ładowanie modułów](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Ustawienia konfiguracji debugowania i profilowania .NET (zmienne profilera CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
