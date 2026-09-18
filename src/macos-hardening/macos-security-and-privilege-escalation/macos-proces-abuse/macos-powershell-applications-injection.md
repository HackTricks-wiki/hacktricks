# Injection von PowerShell-Anwendungen unter macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell ist plattformübergreifend: Dieselbe `pwsh`-Binärdatei läuft unter macOS, Linux und Windows und ist eine **.NET-(Core-)Anwendung**. Dadurch erhält ein Angreifer, der die Umgebung eines `pwsh`-Aufrufs kontrolliert, mehrere Primitives für die Codeausführung über Umgebungsvariablen, die auf allen drei Betriebssystemen identisch funktionieren, sowie einige weitere, die nur unter Windows verfügbar sind. Sie alle werden **vor** (oder anstelle) des vom Opfer beabsichtigten `-Command`/`-File` ausgeführt. Dadurch eignen sie sich ideal für privilegierte Wrapper, cron-/`launchd`-/systemd-Jobs und CI runner, die `pwsh` mit einer geerbten Umgebung aufrufen und dabei eine Shell verwenden.

## `XDG_CONFIG_HOME` und PowerShell-Profile

Unter macOS und Linux verwendet PowerShell XDG-Konfigurationspfade und führt beim Start von `pwsh` Benutzerprofilscripts aus. Durch die Umleitung von `XDG_CONFIG_HOME` wird das Verzeichnis geändert, das `powershell/profile.ps1` und das konsolenhostspezifische `powershell/Microsoft.PowerShell_profile.ps1` enthält. Eine kontrollierte Datei an dieser Stelle kann daher vor einem `-Command`-Payload ausgeführt werden.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Dies gilt für PowerShell 6+ (`pwsh`) auf Nicht-Windows-Plattformen; Windows PowerShell verwendet andere Profilpfade. `pwsh -NoProfile` unterdrückt das Laden von Profilen. Prüfe außerdem `HOME` und hostspezifische Profilnamen, da andere PowerShell-Hosts möglicherweise andere Skripte auswählen.

> [!TIP]
> Unter **Windows** werden die Profilpfade aus `$HOME` / dem bekannten Ordner *Documents* abgeleitet (z. B. `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` für `pwsh`, `Documents\WindowsPowerShell\...` für Windows PowerShell). Daher ist das Beeinflussen von `HOME`/`USERPROFILE` — oder einfach das Schreiben dieser Datei — das entsprechende Primitive.

## Hijacking des automatischen Ladens von `PSModulePath`-Modulen

Seit PowerShell 3.0 importiert das **automatische Laden von Modulen** ein Modul automatisch, sobald erstmals auf einen von ihm exportierten Befehl verwiesen wird (durch Aufruf, `Get-Command` oder Tab-Vervollständigung). PowerShell durchsucht rekursiv jedes in **`$Env:PSModulePath`** aufgeführte Verzeichnis nach `.psd1`-/`.psm1`-Dateien, und auf Nicht-Windows-Systemen wird der vom Prozess geerbte Wert von `PSModulePath` unverändert berücksichtigt. Wenn du **ein Verzeichnis an den Anfang von `PSModulePath` setzen** kannst, kannst du ein Modul platzieren, das entweder einem Befehl entspricht, den das Opfer-Skript aufruft, oder einem Modulnamen, den das Skript mit `Import-Module` importiert — und dein Code auf Modulebene wird zum Zeitpunkt des Imports ausgeführt.<sup>[[3]](#references)</sup>

Da die PowerShell-Befehlsauflösung nach dem Schema *Alias → Function → Cmdlet → Application* erfolgt, kann eine von deinem Modul exportierte **Function** ein integriertes Cmdlet überschreiben, das das Ziel verwendet (z. B. `Get-ChildItem`). Daher muss das Opfer nicht einmal explizit etwas anhand seines Namens importieren.
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
Unter **Windows** gilt dasselbe (`;`-getrennte Pfade); `PSModulePath` bezieht außerdem Werte aus `HKCU:\Environment` und `HKLM:\...\Session Manager\Environment`, sodass ein beschreibbarer Wert im Benutzerbereich ebenfalls ein Persistence-Primitiv ist. Auto-loading kann mit `$PSModuleAutoloadingPreference = 'None'` deaktiviert werden, und `pwsh -NoProfile` verhindert dies **nicht**.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` läuft auf .NET Core, sodass die **CLR profiling API** beim Start eine Angreifer-DLL/`.so`/`.dylib` allein aus der Umgebung in den Prozess lädt — keine Signatur und keine COM-Registrierung erforderlich, da die `*_PATH`-Variablen Vorrang vor der Registry haben. Die `DllMain`/der Einstiegspunkt der Profiler-Bibliothek wird innerhalb des PowerShell-Prozesses ausgeführt, was eine klassische In-Process-Codeausführung- und Persistence-Technik darstellt (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- Bei **.NET 8+** können die Variablen auch das neuere Präfix `DOTNET_` verwenden (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` bleibt aus Gründen der Abwärtskompatibilität erhalten.
- Unter **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) lautet das entsprechende Trio **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** und **`COR_PROFILER_PATH=C:\evil.dll`**.

Die Profiler-DLL muss lediglich eine gültige COM/ICorProfilerCallback-Bibliothek sein (oder ihre Aufgabe einfach aus `DllMain` heraus erledigen). Defensive Launcher sollten `COR_*`/`CORECLR_*`/`DOTNET_*` aus privilegierten Umgebungen entfernen.

## `DOTNET_STARTUP_HOOKS` ( .NET-Hook vor `Main`)

Da `pwsh` eine .NET-Core-Anwendung ist, verweist **`DOTNET_STARTUP_HOOKS`** auf eine verwaltete Assembly, deren `StartupHook.Initialize()` synchron vor dem `Main` des Hosts ausgeführt wird – also bevor PowerShell selbst startet. Dies ist die sauberste Primitive für verwalteten Code und wird von jeder anderen .NET-Anwendung gemeinsam genutzt:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Umgehung der Windows-Kontrolle)

Unter Windows überschreibt das Setzen der Umgebungsvariable **`$Env:PSExecutionPolicyPreference`** (z. B. auf `Bypass` oder `Unrestricted`) die effektive Execution Policy für diesen Prozess – genau das schreibt `Set-ExecutionPolicy -Scope Process`. Dies führt nicht selbst Code aus, entfernt jedoch die Schutzmaßnahme „nicht signierte Skripte werden blockiert“, die häufig das fehlende Bindeglied ist, damit eine der oben genannten Primitives (ein platziertes Profil / Modul) tatsächlich ausgeführt wird. Die Execution Policy gilt nur für Windows und war nie eine Sicherheitsgrenze.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell-Umgebungsvariablen und XDG-Pfade](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell-Profile](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath und automatisches Laden von Modulen](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET-Debugging- und Profiling-Konfigurationseinstellungen (CORECLR_/DOTNET_-Profiler-Variablen)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
