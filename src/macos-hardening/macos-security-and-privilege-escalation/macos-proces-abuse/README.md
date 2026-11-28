# macOS Process Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir; ancak süreçler kod çalıştırmaz, bunu thread'ler yapar. Dolayısıyla **süreçler; çalışan thread'ler için bellek, tanımlayıcılar, portlar, izinler gibi kaynakları sağlayan kapsayıcılardır**.

Geleneksel olarak süreçler (PID 1 hariç) **`fork`** çağrısıyla başka süreçlerin içinde başlatılırdı. Bu çağrı, mevcut sürecin tam bir kopyasını oluştururdu; ardından **alt süreç** genellikle yeni yürütülebilir dosyayı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Daha sonra, bellek kopyalamadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`vfork`** ile **`execve`** işlemlerini tek bir çağrıda birleştiren ve bayrakları kabul eden **`posix_spawn`** kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu ilişkisini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Sinyal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec yap (`execve` gibi, ancak daha fazla seçenekle)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'un Nano ayırıcısını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` kullanımına izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaydırmasının üst bitlerini rastgeleleştir

Ayrıca `posix_spawn`, oluşturulan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç sonlandığında **dönüş kodunu `SIGCHLD` sinyaliyle üst sürece gönderir** (üst süreç sonlanmışsa yeni üst süreç PID 1 olur). Üst süreç bu değeri `wait4()` veya `waitid()` çağrısıyla almalıdır. Bu gerçekleşene kadar alt süreç zombi durumunda kalır; listelenmeye devam eder ancak kaynak tüketmez.

### PID'ler

PID'ler (süreç tanımlayıcıları), benzersiz bir süreci tanımlar. XNU'da **PID'ler** 64 bittir, monotonik olarak artar ve **asla başa sarmaz** (kötüye kullanımı önlemek için).

### Süreç Grupları, Oturumlar ve Koalisyonlar

**Süreçler**, yönetimlerini kolaylaştırmak için **gruplara** yerleştirilebilir. Örneğin, bir kabuk betiğindeki komutlar aynı süreç grubunda olur; böylece örneğin `kill` kullanarak **hepsine birlikte sinyal göndermek** mümkün olur.\
Süreçleri **oturumlar halinde gruplamak** da mümkündür. Bir süreç oturum başlattığında (`setsid(2)`), kendi oturumlarını başlatmadıkları sürece alt süreçler bu oturuma dahil edilir.

Koalisyon, Darwin'de süreçleri gruplandırmanın başka bir yoludur. Bir koalisyona katılan süreç, havuz kaynaklarına erişebilir, bir ledger'ı paylaşabilir veya Jetsam ile karşılaşabilir. Koalisyonların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personae

Her süreç, sistemdeki **ayrıcalıklarını tanımlayan kimlik bilgilerini** taşır. Her sürecin bir birincil `uid` ve bir birincil `gid` değeri vardır (ancak birden fazla gruba üye olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliğini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli işlevler bulunur.

**`persona`** sistem çağrısı, alternatif bir **kimlik bilgileri** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve grup üyeliklerini **aynı anda** üstlenir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) struct'ı bulmak mümkündür:

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

## Threads Hakkında Temel Bilgiler

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir thread API'sinin parçası olan POSIX thread'lerini (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak `bsdthread_create()` işlevini çağırır. Bu, macOS'un temel aldığı XNU kernel'ine özgü daha düşük seviyeli bir sistem çağrısıdır. Sistem çağrısı, thread davranışını belirleyen zamanlama politikaları ve stack boyutu dahil olmak üzere `pthread_attr` (öznitelikler) üzerinden alınan çeşitli bayrakları kullanır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu boyut tipik işlemler için yeterlidir, ancak daha fazla veya daha az alana ihtiyaç duyulursa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında önemli bir rol oynar ve stack'in konumu ile boyutuyla ilgili bilgileri içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'lerden Çıkma:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, thread'in temiz biçimde çıkmasını, gerekli temizliği yapmasını ve bir dönüş değerini thread'i bekleyen diğer thread'lere göndermesini sağlar.
2. **Thread Temizliği:** `pthread_exit()` çağrıldığında, ilişkili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread portlarını (Mach, XNU kernel'indeki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel düzeyindeki yapıları kaldıran bir sistem çağrısı olan `bsdthread_terminate`'i çağırır.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli senkronizasyon ilkelleri sağlar. Bunlar, veri bütünlüğünü ve sistem kararlılığını sağlamak için çok thread'li ortamlarda kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (İmza: 0x4D555458):** 60 bayt bellek kullanan standart mutex (mutex için 56 bayt ve imza için 4 bayt).
   - **Fast Mutex (İmza: 0x4d55545A):** Normal mutex'e benzer, ancak daha hızlı işlemler için optimize edilmiştir; boyutu da 60 bayttır.
2. **Condition Variable'lar:**
   - Belirli koşulların oluşmasını beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık imza).
   - **Condition Variable Öznitelikleri (İmza: 0x434e4441):** 12 bayt boyutundaki condition variable yapılandırma öznitelikleri.
3. **Once Variable (İmza: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Birden fazla okuyucuya veya aynı anda tek bir yazıcıya izin vererek paylaşılan verilere verimli erişim sağlar.
   - **Read-Write Lock (İmza: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read-Write Lock Öznitelikleri (İmza: 0x52574c41):** Boyutu 20 bayt olan read-write lock öznitelikleri.

> [!TIP]
> Bu nesnelerin son 4 baytı taşmaları tespit etmek için kullanılır.

### Thread-Local Değişkenler (TLV)

Mach-O dosyaları (macOS'taki yürütülebilir dosya biçimi) bağlamında **Thread-Local Variables (TLV)**, çok thread'li bir uygulamada **her thread'e özgü** değişkenleri tanımlamak için kullanılır. Böylece her thread'in değişkenden kendine ait ayrı bir kopyası olur. Bu, mutex gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemeye ve veri bütünlüğünü korumaya yardımcı olur.

C ve ilgili dillerde, thread-local bir değişkeni **`__thread`** anahtar sözcüğünü kullanarak tanımlayabilirsiniz. Örneğinizde şöyle çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu kod parçacığı, `tlv_var` değişkenini thread-local olarak tanımlar. Bu kodu çalıştıran her thread kendi `tlv_var` değişkenine sahip olur ve bir thread'in `tlv_var` üzerinde yaptığı değişiklikler başka bir thread'in `tlv_var` değişkenini etkilemez.

Mach-O binary dosyasında, thread-local değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, thread-local değişkenlerin türleri ve başlatılma durumları gibi meta verileri içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış thread-local değişkenler için kullanılır. Sıfırla başlatılan veriler için ayrılmış belleğin bir parçasıdır.

Mach-O, bir thread sonlandığında thread-local değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API de sağlar. Bu API, bir thread sonlandığında thread-local verileri temizleyen özel işlevler olan **destructor'ları kaydetmenizi** sağlar.

### Thread Öncelikleri

Thread önceliklerini anlamak, işletim sisteminin hangi thread'leri ne zaman çalıştıracağına nasıl karar verdiğine bakmayı gerektirir. Bu karar, her thread'e atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla yönetilir.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir `nice` değeri vardır. Bir süreç oluşturulduğunda varsayılan `nice` değeri genellikle 0'dır.
   - Daha düşük bir `nice` değeri (-20'ye daha yakın), sürecin daha "bencil" olmasını ve `nice` değeri daha yüksek olan diğer süreçlere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
   - `renice`, çalışmakta olan bir sürecin `nice` değerini değiştirmek için kullanılan bir komuttur. Yeni `nice` değerlerine bağlı olarak süreçlerin CPU zamanı tahsisini artırmak veya azaltmak için öncelikleri dinamik olarak ayarlamada kullanılabilir.
   - Örneğin, bir süreç geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa `renice` kullanarak `nice` değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde thread önceliklerini yönetmek için daha modern bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre farklı kategorilere **ayırmasını** sağlar. macOS, thread önceliklerini bu QoS sınıflarına göre otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla o anda etkileşimde olan veya iyi bir kullanıcı deneyimi sunmak için anında sonuç gerektiren görevler içindir. Arayüzün yanıt verebilir kalması için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açmak veya hesaplama gerektiren bir düğmeye tıklamak gibi, kullanıcının başlattığı ve hemen sonuç beklediği görevler içindir. Bunlar yüksek önceliklidir ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Bu sınıf, uzun süren ve genellikle bir ilerleme göstergesi sunan görevler içindir (ör. dosya indirme, veri içe aktarma). Öncelikleri User Initiated görevlerden düşüktür ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Bu sınıf, arka planda çalışan ve kullanıcı tarafından görülmeyen görevler içindir. Dizin oluşturma, senkronizasyon veya yedekleme gibi görevler buna örnektir. En düşük önceliğe sahiptirler ve sistem performansını en az düzeyde etkilerler.

Geliştiriciler, QoS sınıflarını kullanarak kesin öncelik numaralarını yönetmek yerine görevin niteliğine odaklanabilir; sistem de CPU kaynaklarını buna göre en iyi şekilde kullanır.

Ayrıca, zamanlayıcının dikkate alacağı zamanlama parametrelerini belirleyen farklı **thread zamanlama politikaları** vardır. Bunlar `thread_policy_[set/get]` kullanılarak ayarlanabilir. Bu, race condition saldırılarında yararlı olabilir.

## macOS Süreç Kötüye Kullanımı

macOS, **süreçlerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sunar. Bu mekanizmalar sistemin normal çalışması için gerekli olsa da saldırganlar bunları injection, code execution veya veri erişimi için kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir kütüphane yüklemeye zorladığı** bir tekniktir. Kütüphane inject edildikten sonra hedef sürecin bağlamında çalışır ve saldırgana süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodu içindeki işlev çağrılarını veya mesajları **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek bir sürecin davranışını **değiştirebilir**, hassas verileri gözlemleyebilir ve hatta yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind meta verileri, arm64e PAC kısıtlamaları ve yapay çağrı zincirleri ele alınmaktadır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı süreçlerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC birçok meşru uygulama için temel olsa da süreç yalıtımını bozmak, hassas bilgileri leak etmek veya yetkisiz eylemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli env değişkenleriyle çalıştırılan Electron uygulamaları process injection saldırılarına karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'leri kullanılarak tuş vuruşlarını ve trafiği çalabilen, cookie'leri ele geçirebilen, sayfalara script inject edebilen bir **man in the browser saldırısı** gerçekleştirilebilir:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini** ve bunların etkileşimlerini **tanımlar**. Ancak bu dosyalar **keyfi komutlar çalıştırabilir** ve **Gatekeeper, bir NIB dosyası değiştirilmişse daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını engellemez**. Dolayısıyla, keyfi programlara keyfi komutlar çalıştırmak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçeneklerini inject etmek ve uygulama başlamadan önce bir Java veya native agent yüklemek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (dosya) veya `--import data:text/javascript,…` (dosyasız, Node ≥ 20.6) üzerinden saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`**, bir modülü etkileşimli REPL'e yükler ve **`ELECTRON_RUN_AS_NODE`**, bunların tümünü Electron binary dosyalarında yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` çalışmadan önce **`DOTNET_STARTUP_HOOKS`** aracılığıyla veya önkoşullar mevcut olduğunda .NET debugging işlevselliğini kötüye kullanarak .NET uygulamalarına kod inject etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash, **`BASH_ENV`** dosyasını okur; etkileşimli POSIX shell'leri **`ENV`** dosyasını okur; zsh, **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmaları okur. Her biri, hedeflenen komuttan önce kontrol edilen bir başlangıç dosyasını çalıştırabilir. xtrace etkinleştirildiğinde Bash, **`PS4`** içine yerleştirilmiş bir command substitution'ı da çalıştırır (ör. devralınan **`SHELLOPTS=xtrace`**):

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` çalıştırıldığında shell, programı standart girdiden okur. Bu nedenle, güvenilmeyen yapılandırılmış bir belgeyi önce ayrıştırmadan alt sürecin stdin'ine kopyalayan bir downloader, belgenin tamamını shell kaynak koduna dönüştürmüş olur. Gözlemlenen bir loader, herkese açık bir iCalendar dosyasını anonim bir pipe üzerinden satır satır aktardı. Takvim meta verileri komut olarak başarısız oldu ancak zsh, `DESCRIPTION:` sonrasına yerleştirilen çalıştırılabilir satırlara ulaşana kadar devam etti. Bu satırlar sonraki uygulama bundle'ını indirip başlattı. Taşıyıcının beklenen içerik türü ve güvenilir bir sunucuda barındırılması bunu güvenli kılmadı; tehlikeli sınır, baytların bir yorumlayıcıya aktarılmasıydı.<sup>[[5]](#references)</sup>

İlgili aşamalar [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) ve [macOS auto-start locations](../../macos-auto-start-locations.md) bölümlerinde ele alınmaktadır.

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, hedef script'ten önce **`auto_prepend_file`** aracılığıyla çalıştırılan, kontrol edilebilir PHP yapılandırmalarını yükleyebilir.

[PHP configuration and `auto_prepend_file` startup injection](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Bağımsız Lua yorumlayıcısı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özgü varyantı) üzerinden kod ya da bir `@file` çalıştırır.

[Lua `LUA_INIT` startup injection (file and inline code)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerini yönlendirir. Bunun yerine **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ile bir R library path kullanılarak kurulu bir paket otomatik yüklenebilir.

[R startup profiles and package loading](macos-interpreter-startup-file-injection.md#r-startup-profiles-and-package-loading)

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak çalıştırılan depot'u yönlendirir.

[Julia `JULIA_DEPOT_PATH` and `startup.jl` injection](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload dosyası gerektirmeden bir Erlang VM **`-eval`** ifadesi inject edebilir; Elixir iş yükleri de genellikle aynı VM'i başlatır.

[Erlang/Elixir VM flag injection](macos-interpreter-startup-file-injection.md#erlang-and-elixir-vm-flags)

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerini yönlendirir.

[GNU Octave startup-file injection](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh` platformlar arası bir .NET uygulamasıdır; bu nedenle birkaç env değişkeni komut öncesi yürütmeye olanak tanır: **`XDG_CONFIG_HOME`**, başlangıçta çalıştırılan profil script'lerini yönlendirir; **`PSModulePath`**, modüllerin otomatik yüklenmesini ele geçirir (yerleştirilen bir `.psm1` içe aktarma sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir); .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ve **`DOTNET_STARTUP_HOOKS`** değişkenleri ise `Main` öncesinde sürece saldırgan kodu yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin aşağıdaki yöntemlerle keyfi kod çalıştırmasını sağlayan farklı seçenekleri inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için Ruby env değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


[Ruby `RUBYOPT`/`RUBYLIB` loader options](macos-interpreter-startup-file-injection.md#ruby-loader-options)

### Python Injection

**`PYTHONWARNINGS`** ve **`BROWSER`** standart kütüphane zinciri, warning-filter ayrıştırması sırasında bir komut çalıştırabilir. Dosya tabanlı bir alternatif olarak `sitecustomize.py` dosyası **`PYTHONPATH`** üzerine yerleştirilir; böylece normal `site` başlatması, hedef script'ten önce bu dosyayı içe aktarır. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına ulaştığında seçilen bir callable/modülü çalıştırır.

CPython 3.13 ve üzeri sürümlerde **`PYTHONINSPECT`**, PyREPL bir terminalde başlatıldığında script sonrasında bir **`PYTHONSTARTUP`** dosyasını da çalıştırabilir.<sup>[[6]](#references)</sup>

**`pyinstaller`** ile derlenen çalıştırılabilir dosyaların, gömülü bir Python kullanarak çalışıyor olsalar bile bu env değişkenlerini kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

**`VIMINIT`** (ve onun yedeği olan `EXINIT`), normal başlatma sırasında Ex komutları olarak çalıştırılır. Bu nedenle, kurban Vim/Neovim'i kontrol edilen bir ortamda açtığında `:!cmd` / `:call system(...)` kod çalıştırılmasını sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Bunun dışında, Homebrew genellikle Python'ı `/opt/homebrew` altına kurar; burada yerel `admin` grubunun üyeleri başlatıcıyı değiştirebilir. Bu, env değişkeni injection'ı değil, yazılabilir binary dosyasının ele geçirilmesidir; istismar edilebilir olduğunu varsaymadan önce sahipliği ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı tespit edip engelleyen, açık kaynaklı ve **EndpointSecurity** tabanlı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir kaynaktır; şu durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç exec edilirken **injection env değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; bu, o sürece injection uygulamanın önkoşuludur.
- **Electron debugging argümanları** — `--inspect`, `--inspect-brk` ve `--remote-debugging-port`; bunlar bir Electron uygulamasını debug modunda başlatır ve herkesin uygulamaya bağlanıp kod çalıştırmasına olanak tanır.<sup>[[3]](#references)</sup>
- **Farklı ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal bir kullanıcı olarak bir bağlantı oluşturup ayrıcalıklı bir konumu hedef gösterme" şeklindeki klasik yöntem. **Symlink'ler için uyarı verilebilir ancak oluşturulmaları engellenemez**: EndpointSecurity, bağlantı oluşturulmadan önce hedefini göstermez.

### Diğer süreçlerin yaptığı çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), bir sürece kod inject eden diğer **süreçler** hakkında bilgi almak ve ardından bu diğer süreçle ilgili bilgi edinmek için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini görebilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırmak için süreci çalıştıranla **aynı uid** değerine veya **root** yetkisine sahip olmanız gerektiğini unutmayın (işlev süreçle ilgili bilgi döndürür; kod inject etme yöntemi sunmaz).



## References

- [1] [Shield — macOS süreç injection'ını tespit eden açık kaynaklı araç (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity framework](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
- [6] [Python komut satırı ve ortam — `PYTHONINSPECT`](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONINSPECT)
{{#include ../../../banners/hacktricks-training.md}}
