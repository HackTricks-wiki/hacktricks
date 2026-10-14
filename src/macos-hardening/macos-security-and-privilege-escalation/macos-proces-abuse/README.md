# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir; ancak kodu süreçler değil, thread'ler çalıştırır. Dolayısıyla **süreçler, thread'leri çalıştırmak için bellek, tanımlayıcılar, portlar, izinler... sağlayan kapsayıcılardır**.

Geleneksel olarak süreçler (PID 1 hariç) diğer süreçlerin içinden **`fork`** çağrısıyla başlatılırdı. Bu çağrı mevcut sürecin tam bir kopyasını oluşturur ve ardından **alt süreç** genellikle yeni yürütülebilir dosyayı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Daha sonra, bellek kopyalama işlemi olmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından, **`vfork`** ile **`execve`** işlevlerini tek çağrıda birleştiren ve bayrakları kabul eden **`posix_spawn`** kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu üyeliğini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Varsayılan sinyal davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec et (daha fazla seçenek sunan `execve` gibi)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'un Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının yüksek bitlerini rastgeleleştir

Ayrıca `posix_spawn`, başlatılan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç öldüğünde, `SIGCHLD` sinyaliyle **dönüş kodunu üst sürece** gönderir (üst süreç ölmüşse yeni üst süreç PID 1 olur). Üst sürecin bu değeri almak için `wait4()` veya `waitid()` çağrısı yapması gerekir. Bu gerçekleşene kadar alt süreç, listelenmeye devam ettiği ancak kaynak tüketmediği zombi durumunda kalır.

### PID'ler

PID'ler (süreç tanımlayıcıları), benzersiz bir süreci tanımlar. XNU'da **PID'ler** **64 bit uzunluğundadır**, monotonik olarak artar ve (kötüye kullanımı önlemek için) **hiçbir zaman başa sarmaz**.

### Süreç Grupları, Oturumlar ve Coalations

**Süreçler**, yönetilmelerini kolaylaştırmak için **gruplara** yerleştirilebilir. Örneğin, bir kabuk betiğindeki komutlar aynı süreç grubunda olur; böylece örneğin kill kullanılarak **bunlara birlikte sinyal gönderilebilir**.\
Süreçleri **oturumlarda gruplamak** da mümkündür. Bir süreç bir oturum başlattığında (`setsid(2)`), kendi oturumlarını başlatmadıkları sürece alt süreçler bu oturumun içinde yer alır.

Coalition, Darwin'deki süreçleri gruplamanın başka bir yoludur. Bir sürecin bir coalition'a katılması, havuz kaynaklarına erişmesini, bir defteri paylaşmasını veya Jetsam'e maruz kalmasını sağlar. Coalition'ların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personae

Her süreç, sistemdeki **ayrıcalıklarını belirleyen** **kimlik bilgilerini** taşır. Her sürecin bir birincil `uid` ve bir birincil `gid` değeri olur (ancak birden fazla gruba üye olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliklerini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli işlevler bulunur.

**`persona`** sistem çağrısı, alternatif bir **kimlik bilgileri** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve grup üyeliklerini **tek seferde** üstlenmek anlamına gelir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) şu struct bulunabilir:

```c
struct kpersona_info { uint32_t persona_info_version;
    uid_t    persona_id; /* overlaps with UID */
    int      persona_type;
    gid_t    persona_gid;
    uint32_t persona_ngroups;
    gid_t    persona_groups[NGROUPS];
    uid_t    persona_gmuid;
    char     persona_name[MAXLOGNAME + 1];

    /* TODO: MAC policies?! */
}
```

## Thread'ler Hakkında Temel Bilgiler

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir thread API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'teki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak XNU kernel'e (macOS'in temel aldığı kernel) özgü daha düşük seviyeli bir sistem çağrısı olan `bsdthread_create()` işlevini çağırır. Bu sistem çağrısı, thread davranışını belirleyen zamanlama ilkeleri ve stack boyutu da dahil olmak üzere `pthread_attr` (öznitelikler) üzerinden alınan çeşitli flag'leri kullanır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu, tipik işlemler için yeterlidir; daha fazla veya daha az alana ihtiyaç duyulursa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, stack'in konumu ve boyutuyla ilgili bilgileri içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanarak thread kurulumu sırasında önemli bir rol oynar.

#### macOS'te Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, bir thread'in gerekli temizleme işlemlerini yaparak düzgün biçimde çıkmasını ve bir dönüş değerini kendisine katılan thread'lere iletmesini sağlar.
2. **Thread Temizliği:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread portlarını (Mach, XNU kernel'deki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel düzeyindeki yapıları kaldıran bir syscall olan `bsdthread_terminate` işlevini çağırır.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli senkronizasyon ilkelleri sağlar. Bunlar, veri bütünlüğünü ve sistem kararlılığını sağlamak açısından multi-threading ortamlarında kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (İmza: 0x4D555458):** Bellekte 60 bayt yer kaplayan standart mutex (mutex için 56 bayt, imza için 4 bayt).
   - **Fast Mutex (İmza: 0x4d55545A):** Normal mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir ve yine 60 bayt boyutundadır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık imza).
   - **Condition Variable Öznitelikleri (İmza: 0x434e4441):** Boyutu 12 bayt olan condition variable yapılandırma öznitelikleri.
3. **Once Variable (İmza: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Paylaşılan verilere verimli erişim sağlayarak aynı anda birden fazla okuyucuya veya tek bir yazıcıya izin verir.
   - **Read Write Lock (İmza: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read Write Lock Öznitelikleri (İmza: 0x52574c41):** Boyutu 20 bayt olan read-write lock öznitelikleri.

> [!TIP]
> Bu nesnelerin son 4 baytı overflow'ları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'teki yürütülebilir dosya biçimi) bağlamında **Thread Local Variables (TLV)**, multi-threaded bir uygulamadaki **her thread'e** özgü değişkenleri tanımlamak için kullanılır. Bu sayede her thread'in kendine ait ayrı bir değişken örneği olur; mutex gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemek ve veri bütünlüğünü korumak mümkün hale gelir.

C ve ilgili dillerde, **`__thread`** anahtar sözcüğünü kullanarak thread-local bir değişken tanımlayabilirsiniz. Örneğinizde şöyle çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu kod parçacığı, `tlv_var` değişkenini iş parçacığına özgü bir değişken olarak tanımlar. Bu kodu çalıştıran her iş parçacığının kendine ait bir `tlv_var` değişkeni olur ve bir iş parçacığının `tlv_var` üzerinde yaptığı değişiklikler başka bir iş parçacığındaki `tlv_var` değişkenini etkilemez.

Mach-O ikili dosyasında iş parçacığına özgü değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, iş parçacığına özgü değişkenlerin türleri ve başlatılma durumları gibi meta verileri içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış iş parçacığına özgü değişkenler için kullanılır. Sıfırla başlatılan veriler için ayrılmış bellek bölümüdür.

Mach-O, bir iş parçacığı sona erdiğinde iş parçacığına özgü değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API de sağlar. Bu API, iş parçacığı sona erdiğinde iş parçacığına özgü verileri temizleyen özel işlevler olan **yıkıcıları kaydetmenize** olanak tanır.

### İş parçacığı öncelikleri

İş parçacığı önceliklerini anlamak için işletim sisteminin hangi iş parçacıklarını ne zaman çalıştıracağına nasıl karar verdiğine bakmak gerekir. Bu karar, her iş parçacığına atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla ele alınır.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir nice değeri vardır. Bir süreç oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
   - Daha düşük bir nice değeri (-20'ye daha yakın), süreci daha "bencil" hâle getirir ve nice değeri daha yüksek olan diğer süreçlere kıyasla daha fazla CPU süresi almasını sağlar.
2. **Renice:**
   - `renice`, zaten çalışan bir sürecin nice değerini değiştirmek için kullanılan bir komuttur. Yeni nice değerlerine göre CPU süresi tahsisini artırıp azaltarak süreçlerin önceliğini dinamik biçimde ayarlamak için kullanılabilir.
   - Örneğin, bir sürecin geçici olarak daha fazla CPU kaynağına ihtiyacı varsa `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde iş parçacığı önceliklerini ele almanın daha modern bir yoludur. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre **kategorilere ayırmasını** sağlar. macOS, iş parçacıklarının önceliklendirilmesini bu QoS sınıflarına göre otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, o sırada kullanıcıyla etkileşim hâlinde olan veya iyi bir kullanıcı deneyimi sunmak için anında sonuç gerektiren görevler içindir. Arayüzün yanıt verebilir kalması için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açmak veya hesaplama gerektiren bir düğmeye tıklamak gibi, kullanıcının başlattığı ve anında sonuç beklediği görevlerdir. Bunlar yüksek önceliklidir ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Bunlar uzun süre çalışan ve genellikle ilerleme göstergesi sunan görevlerdir (ör. dosya indirme, veri içe aktarma). Kullanıcının başlattığı görevlerden daha düşük önceliğe sahiptir ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Bu sınıf, arka planda çalışan ve kullanıcıya görünmeyen görevler içindir. Dizin oluşturma, eşitleme veya yedekleme gibi işler bu görevler arasında yer alabilir. En düşük önceliğe sahiptirler ve sistem performansına etkileri en azdır.

QoS sınıfları sayesinde geliştiricilerin kesin öncelik numaralarını yönetmesi gerekmez; bunun yerine görevin niteliğine odaklanabilirler ve sistem CPU kaynaklarını buna göre en iyi şekilde kullanır.

Ayrıca, zamanlayıcının dikkate alacağı bir dizi zamanlama parametresi belirtmek için kullanılan farklı **iş parçacığı zamanlama ilkeleri** vardır. Bu, `thread_policy_[set/get]` kullanılarak yapılabilir. Bu, race condition saldırılarında işe yarayabilir.

## macOS süreçlerinin kötüye kullanımı

macOS, **süreçlerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar sistemin normal çalışması için gerekli olsa da saldırganlar bunları injection, code execution veya veri erişimi için kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir kütüphane yüklemeye zorladığı** bir tekniktir. Kütüphane enjekte edildikten sonra hedef sürecin bağlamında çalışır ve saldırgana bu süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodundaki **işlev çağrılarını** veya iletileri **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir sürecin **davranışını değiştirebilir**, hassas verileri gözlemleyebilir veya yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind meta verileri, arm64e PAC kısıtlamaları ve sentetik çağrı zincirleri ele alınmaktadır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Süreçler Arası İletişim

Süreçler Arası İletişim (IPC), ayrı süreçlerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC, birçok meşru uygulama için temel olsa da süreç yalıtımını aşmak, hassas bilgileri leak etmek veya yetkisiz eylemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli ortam değişkenleriyle çalıştırılan Electron uygulamaları süreç injection saldırılarına karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

Tuş vuruşlarını ve trafiği çalmaya, çerezleri ele geçirmeye, sayfalara script enjekte etmeye vb. olanak tanıyan bir **man in the browser attack** gerçekleştirmek için `--load-extension` ve `--use-fake-ui-for-media-stream` flag'lerini kullanmak mümkündür:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini** ve bunların etkileşimlerini **tanımlar**. Ancak **keyfi komutlar çalıştırabilirler** ve **NIB dosyası değiştirilse bile Gatekeeper daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını engellemez**. Bu nedenle, keyfi programlara keyfi komutlar çalıştırmaları için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

Uygulama başlamadan önce **`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri enjekte edip bir Java veya native agent yüklemek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (dosya) veya `--import data:text/javascript,…` (dosyasız, Node ≥ 20.6) üzerinden saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** bir modülü etkileşimli REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`** tüm bunları Electron ikili dosyalarında yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` öncesinde **`DOTNET_STARTUP_HOOKS`** aracılığıyla .NET uygulamalarına kod enjekte etmek veya ön koşullar sağlandığında .NET debugging işlevselliğini kötüye kullanmak mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimli olmayan Bash **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmaları okur. Bunların her biri, hedeflenen komuttan önce denetlenen bir başlangıç dosyasını çalıştırabilir. Bash ayrıca xtrace etkin olduğunda (ör. devralınan **`SHELLOPTS=xtrace`** ile) **`PS4`** içine yerleştirilmiş bir command substitution'ı çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` başlatıldığında shell, bir programı standart girdiden okur. Dolayısıyla, güvenilmeyen yapılandırılmış bir belgeyi önce ayrıştırmadan çocuğun stdin akışına kopyalayan bir downloader, belgenin tamamını shell kaynak koduna dönüştürmüş olur. Gözlemlenen bir loader, herkese açık bir iCalendar dosyasını anonim bir pipe üzerinden satır satır iletti. Takvim meta verileri komut olarak çalışmadı, ancak `DESCRIPTION:` sonrasına yerleştirilmiş çalıştırılabilir satırlara ulaşana kadar zsh çalışmaya devam etti. Bu satırlar sonraki uygulama paketini indirip başlattı. Taşıyıcının beklenen içerik türüne sahip olması ve güvenilir bir sunucuda barındırılması bunu güvenli hâle getirmedi; tehlikeli sınır, baytların bir yorumlayıcıya aktarılmasıydı.<sup>[[5]](#references)</sup>

İlgili aşamalar [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) ve [macOS auto-start locations](../../macos-auto-start-locations.md) bölümlerinde ele alınmaktadır.

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, hedef script'ten önce çalışan **`auto_prepend_file`** içeren, denetlenen PHP yapılandırmalarını yükleyebilir.

{{#ref}}
macos-php-applications-injection.md
{{#endref}}

### Lua Injection

Tek başına çalışan Lua yorumlayıcısı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özgü karşılığında) belirtilen kodu ya da bir `@file` dosyasını çalıştırır.

{{#ref}}
macos-lua-applications-injection.md
{{#endref}}

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerine yönlendirir. Bunun yerine, **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ve bir R kütüphane yolu kullanılarak kurulu bir paket otomatik yüklenebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak çalıştırılan depot'u başka bir konuma yönlendirir.

{{#ref}}
macos-julia-applications-injection.md
{{#endref}}

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload dosyası gerektirmeden bir Erlang VM **`-eval`** ifadesi enjekte edebilir; Elixir iş yükleri genellikle aynı VM'i başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerini başka konumlara yönlendirir.

{{#ref}}
macos-octave-applications-injection.md
{{#endref}}

### PowerShell Injection

`pwsh` platformlar arası bir .NET uygulamasıdır; bu nedenle birkaç ortam değişkeni komut öncesinde kod çalıştırılmasına olanak tanır: **`XDG_CONFIG_HOME`** başlangıçta çalışan profil script'lerini başka konuma yönlendirir, **`PSModulePath`** modüllerin otomatik yüklenmesini ele geçirir (yerleştirilen bir `.psm1` içe aktarma sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir) ve .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ile **`DOTNET_STARTUP_HOOKS`** değişkenleri, `Main` öncesinde sürece saldırgan kodu yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin keyfi kod çalıştırmasını sağlayacak farklı seçeneklere göz atın:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için Ruby ortam değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standart kütüphane zinciri, uyarı filtresi ayrıştırması sırasında bir komut çalıştırabilir. Dosya kullanan alternatif bir yöntemde `sitecustomize.py`, hedef script'ten önce normal `site` başlatma işlemi sırasında içe aktarılması için **`PYTHONPATH`** üzerine yerleştirilir. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına ulaştığında seçilen bir callable/modülü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli oturumlarda kullanılan değişkenlerin kullanım alanı daha dardır.

**`pyinstaller`** ile derlenen çalıştırılabilir dosyaların, gömülü bir Python kullanarak çalışsalar bile bu ortam değişkenlerini kullanmadığını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve yedek seçeneği olan `EXINIT`), normal başlatma sırasında Ex komutları olarak çalıştırılır. Bu nedenle, kurban Vim/Neovim'i denetlenen bir ortamla açtığında `:!cmd` / `:call system(...)` kod çalıştırılmasını sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Bunun dışında, Homebrew genellikle Python'ı `/opt/homebrew` altına yükler; burada yerel `admin` grubunun üyeleri başlatıcıyı değiştirebilir. Bu, ortam değişkeni injection'ı değil, yazılabilir ikili dosyanın ele geçirilmesidir; bunu istismar edilebilir kabul etmeden önce sahipliği ve ACL'leri doğrulayın.


## Tespit

### Shield

[**Shield**](https://github.com/theevilbit/Shield), süreç injection'ını tespit edip engelleyen, açık kaynaklı ve **EndpointSecurity** tabanlı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir kaynaktır; şu durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç çalıştırılırken **injection ortam değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; o sürece injection yapmak için gereken ön koşul.
- **Electron debugging argümanları** — bir Electron uygulamasını debug modunda başlatıp herhangi birinin bağlanarak uygulamada kod çalıştırmasına olanak tanıyan `--inspect`, `--inspect-brk` ve `--remote-debugging-port`.<sup>[[3]](#references)</sup>
- **Ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal kullanıcı olarak bir bağlantı oluşturup ayrıcalıklı bir konuma yöneltme" şeklindeki klasik yöntem. **Symlink'ler için uyarı verilebilir ancak bunlar engellenemez**: EndpointSecurity, bağlantı oluşturulmadan önce hedefini göstermez.

### Diğer süreçler tarafından yapılan çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **süreçlere kod enjekte eden süreçler** hakkında bilgi edinmek ve ardından bu diğer süreçle ilgili bilgileri almak için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için süreci çalıştıran kullanıcıyla **aynı uid'ye** veya **root** yetkisine sahip olmanız gerektiğini unutmayın (işlev, kod enjekte etmenin bir yolunu değil, süreç hakkındaki bilgileri döndürür).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — açık kaynaklı macOS süreç injection tespiti (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
