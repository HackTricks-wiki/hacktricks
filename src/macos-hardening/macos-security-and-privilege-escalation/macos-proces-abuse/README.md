# macOS Süreç İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Süreçler Hakkında Temel Bilgiler

Bir süreç, çalışan bir yürütülebilir dosyanın örneğidir; ancak süreçler kod çalıştırmaz, bunu thread'ler yapar. Bu nedenle **süreçler, bellek, tanımlayıcılar, portlar, izinler... sağlayan thread kapsayıcılarından ibarettir**.

Geleneksel olarak süreçler (PID 1 hariç) başka süreçlerin içinden **`fork`** çağrısıyla başlatılırdı. Bu çağrı, mevcut sürecin tam bir kopyasını oluştururdu; ardından **alt süreç** genellikle yeni yürütülebilir dosyayı yükleyip çalıştırmak için **`execve`** çağrısı yapardı. Sonrasında, bellek kopyalama işlemi olmadan bu süreci hızlandırmak için **`vfork`** kullanıma sunuldu.\
Ardından **`vfork`** ile **`execve`**'yi tek çağrıda birleştiren ve aşağıdaki bayrakları kabul eden **`posix_spawn`** kullanıma sunuldu:

- `POSIX_SPAWN_RESETIDS`: Etkin kimlikleri gerçek kimliklere sıfırla
- `POSIX_SPAWN_SETPGROUP`: Süreç grubu üyeliğini ayarla
- `POSUX_SPAWN_SETSIGDEF`: Sinyal varsayılan davranışını ayarla
- `POSIX_SPAWN_SETSIGMASK`: Sinyal maskesini ayarla
- `POSIX_SPAWN_SETEXEC`: Aynı süreçte exec yap (`execve` ile benzer, ancak daha fazla seçenek sunar)
- `POSIX_SPAWN_START_SUSPENDED`: Askıya alınmış olarak başlat
- `_POSIX_SPAWN_DISABLE_ASLR`: ASLR olmadan başlat
- `_POSIX_SPAWN_NANO_ALLOCATOR:` libmalloc'ın Nano allocator'ını kullan
- `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Veri segmentlerinde `rwx` iznine izin ver
- `POSIX_SPAWN_CLOEXEC_DEFAULT`: Varsayılan olarak exec(2) sırasında tüm dosya tanımlayıcılarını kapat
- `_POSIX_SPAWN_HIGH_BITS_ASLR:` ASLR kaymasının yüksek bitlerini rastgeleleştir

Ayrıca `posix_spawn`, oluşturulan sürecin özelliklerini denetleyen **`posix_spawnattr`** ayarlarını ve dosya tanımlayıcılarını değiştiren **`posix_spawn_file_actions`** girdilerini kabul eder.

Bir süreç öldüğünde, `SIGCHLD` sinyaliyle **dönüş kodunu üst sürece** gönderir (üst süreç öldüyse yeni üst süreç PID 1 olur). Üst süreç bu değeri `wait4()` veya `waitid()` çağrısıyla almalıdır. Bu gerçekleşene kadar alt süreç zombi durumunda kalır; listede görünmeye devam eder ancak kaynak tüketmez.

### PID'ler

PID'ler (süreç tanımlayıcıları), benzersiz bir süreci tanımlar. XNU'da **PID'ler** **64 bittir**, monotonik olarak artar ve (istismarları önlemek için) **asla başa sarmaz**.

### Süreç Grupları, Oturumlar ve Koalisyonlar

**Süreçler**, yönetimi kolaylaştırmak için **gruplar** hâlinde toplanabilir. Örneğin, bir shell script'indeki komutlar aynı süreç grubunda olur; böylece örneğin `kill` kullanarak **hepsine birlikte sinyal göndermek** mümkün olur.\
Süreçleri **oturumlar hâlinde gruplamak** da mümkündür. Bir süreç oturum başlattığında (`setsid(2)`), kendi oturumlarını başlatmadıkları sürece alt süreçler bu oturuma dâhil edilir.

Koalisyon, Darwin'de süreçleri gruplamanın başka bir yoludur. Bir sürecin koalisyona katılması, havuz kaynaklarına erişmesini, bir ledger'ı paylaşmasını veya Jetsam'e tabi olmasını sağlar. Koalisyonların farklı rolleri vardır: Leader, XPC service, Extension.

### Kimlik Bilgileri ve Personalar

Her süreç, sistemdeki ayrıcalıklarını **belirleyen kimlik bilgilerine** sahiptir. Her sürecin bir birincil `uid` ve bir birincil `gid` değeri vardır (birden fazla gruba üye olabilir).\
İkili dosyada `setuid/setgid` biti varsa kullanıcı ve grup kimliğini değiştirmek de mümkündür.\
**Yeni uid/gid değerleri ayarlamak** için çeşitli işlevler vardır.

**`persona`** sistem çağrısı, alternatif bir **kimlik bilgileri** kümesi sağlar. Bir persona'yı benimsemek, onun uid, gid ve grup üyeliklerinin **tamamını aynı anda** üstlenir. [**Kaynak kodunda**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) şu yapıyı bulmak mümkündür:

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

## Threads Temel Bilgileri

1. **POSIX Threads (pthreads):** macOS, C/C++ için standart bir threading API'sinin parçası olan POSIX threads'ü (`pthreads`) destekler. macOS'taki pthreads uygulaması, herkese açık `libpthread` projesinden gelen `/usr/lib/system/libsystem_pthread.dylib` içinde bulunur. Bu kütüphane, thread'leri oluşturmak ve yönetmek için gerekli işlevleri sağlar.
2. **Thread Oluşturma:** Yeni thread'ler oluşturmak için `pthread_create()` işlevi kullanılır. Bu işlev, dahili olarak XNU kernel'e (macOS'un temel aldığı kernel) özgü daha düşük seviyeli bir system call olan `bsdthread_create()` işlevini çağırır. Bu system call, zamanlama ilkeleri ve stack boyutu dahil thread davranışını belirten, `pthread_attr` (öznitelikler) üzerinden türetilen çeşitli flag'leri alır.
   - **Varsayılan Stack Boyutu:** Yeni thread'ler için varsayılan stack boyutu 512 KB'tır. Bu, tipik işlemler için yeterlidir ancak daha fazla veya daha az alana ihtiyaç varsa thread öznitelikleri aracılığıyla ayarlanabilir.
3. **Thread Başlatma:** `__pthread_init()` işlevi, thread kurulumu sırasında kritik öneme sahiptir ve stack'in konumu ile boyutu gibi bilgileri içerebilen ortam değişkenlerini ayrıştırmak için `env[]` argümanını kullanır.

#### macOS'ta Thread Sonlandırma

1. **Thread'lerden Çıkış:** Thread'ler genellikle `pthread_exit()` çağrılarak sonlandırılır. Bu işlev, thread'in düzgün şekilde çıkmasını, gerekli temizliği yapmasını ve join işlemini yapan thread'lere bir dönüş değeri göndermesini sağlar.
2. **Thread Temizliği:** `pthread_exit()` çağrıldığında, ilgili tüm thread yapılarını kaldıran `pthread_terminate()` işlevi çağrılır. Bu işlev, Mach thread portlarını (Mach, XNU kernel'deki iletişim alt sistemidir) serbest bırakır ve thread ile ilişkili kernel düzeyindeki yapıları kaldıran bir syscall olan `bsdthread_terminate`'i çağırır.

#### Senkronizasyon Mekanizmaları

Paylaşılan kaynaklara erişimi yönetmek ve race condition'ları önlemek için macOS çeşitli senkronizasyon ilkelleri sağlar. Bunlar, veri bütünlüğünü ve sistem kararlılığını sağlamak açısından çok thread'li ortamlarda kritik öneme sahiptir:

1. **Mutex'ler:**
   - **Normal Mutex (Signature: 0x4D555458):** 60 baytlık bellek alanına sahip standart mutex (mutex için 56 bayt, signature için 4 bayt).
   - **Fast Mutex (Signature: 0x4d55545A):** Normal mutex'e benzer ancak daha hızlı işlemler için optimize edilmiştir; boyutu yine 60 bayttır.
2. **Condition Variable'lar:**
   - Belirli koşulların gerçekleşmesini beklemek için kullanılır; boyutu 44 bayttır (40 bayt ve 4 baytlık signature).
   - **Condition Variable Öznitelikleri (Signature: 0x434e4441):** Condition variable'lar için yapılandırma öznitelikleri; boyutu 12 bayttır.
3. **Once Variable (Signature: 0x4f4e4345):**
   - Bir başlatma kodu parçasının yalnızca bir kez çalıştırılmasını sağlar. Boyutu 12 bayttır.
4. **Read-Write Lock'lar:**
   - Birden fazla okuyucuya veya aynı anda tek bir yazıcıya izin vererek paylaşılan verilere verimli erişim sağlar.
   - **Read Write Lock (Signature: 0x52574c4b):** Boyutu 196 bayttır.
   - **Read Write Lock Öznitelikleri (Signature: 0x52574c41):** Read-write lock'lar için öznitelikler; boyutu 20 bayttır.

> [!TIP]
> Bu nesnelerin son 4 baytı, taşmaları tespit etmek için kullanılır.

### Thread Local Variables (TLV)

Mach-O dosyaları (macOS'taki yürütülebilir dosya biçimi) bağlamında **Thread Local Variables (TLV)**, çok thread'li bir uygulamada **her thread'e özgü** değişkenleri bildirmek için kullanılır. Böylece her thread kendi ayrı değişken örneğine sahip olur; mutex gibi açık senkronizasyon mekanizmalarına ihtiyaç duymadan çakışmaları önlemek ve veri bütünlüğünü korumak mümkün olur.

C ve ilgili dillerde, thread-local bir değişkeni **`__thread`** anahtar sözcüğünü kullanarak bildirebilirsiniz. Örneğinizde şu şekilde çalışır:

```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
    tlv_var = 10;
}
```

Bu kod parçacığı, `tlv_var` değişkenini iş parçacığına özel bir değişken olarak tanımlar. Bu kodu çalıştıran her iş parçacığının kendine ait bir `tlv_var` değişkeni olur ve bir iş parçacığının `tlv_var` üzerinde yaptığı değişiklikler başka bir iş parçacığındaki `tlv_var` değişkenini etkilemez.

Mach-O ikili dosyasında, iş parçacığına özel değişkenlerle ilgili veriler belirli bölümlerde düzenlenir:

- **`__DATA.__thread_vars`**: Bu bölüm, iş parçacığına özel değişkenlerin türleri ve başlatılma durumu gibi üst verilerini içerir.
- **`__DATA.__thread_bss`**: Bu bölüm, açıkça başlatılmamış iş parçacığına özel değişkenler için kullanılır. Sıfırla başlatılan veriler için ayrılmış belleğin bir parçasıdır.

Mach-O, bir iş parçacığı sona erdiğinde iş parçacığına özel değişkenleri yönetmek için **`tlv_atexit`** adlı özel bir API de sunar. Bu API, iş parçacığı sonlandığında iş parçacığına özel verileri temizleyen özel işlevler olan **yıkıcıları kaydetmenize** olanak tanır.

### İş Parçacığı Öncelikleri

İş parçacığı önceliklerini anlamak için işletim sisteminin hangi iş parçacıklarını ne zaman çalıştıracağına nasıl karar verdiğine bakmak gerekir. Bu karar, her iş parçacığına atanan öncelik düzeyinden etkilenir. macOS ve Unix benzeri sistemlerde bu işlem `nice`, `renice` ve Quality of Service (QoS) sınıfları gibi kavramlarla yönetilir.

#### Nice ve Renice

1. **Nice:**
   - Bir sürecin `nice` değeri, önceliğini etkileyen bir sayıdır. Her sürecin -20 (en yüksek öncelik) ile 19 (en düşük öncelik) arasında bir nice değeri vardır. Bir süreç oluşturulduğunda varsayılan nice değeri genellikle 0'dır.
   - Daha düşük bir nice değeri (-20'ye daha yakın), süreci daha "bencil" hale getirir ve nice değeri daha yüksek süreçlere kıyasla daha fazla CPU zamanı almasını sağlar.
2. **Renice:**
   - `renice`, çalışmakta olan bir sürecin nice değerini değiştirmek için kullanılan bir komuttur. Yeni nice değerlerine göre CPU zamanı tahsisini artırarak veya azaltarak süreçlerin önceliğini dinamik biçimde ayarlamak için kullanılabilir.
   - Örneğin, bir süreç geçici olarak daha fazla CPU kaynağına ihtiyaç duyuyorsa `renice` kullanarak nice değerini düşürebilirsiniz.

#### Quality of Service (QoS) Sınıfları

QoS sınıfları, özellikle **Grand Central Dispatch (GCD)** desteği sunan macOS gibi sistemlerde, iş parçacığı önceliklerini yönetmeye yönelik daha yeni bir yaklaşımdır. QoS sınıfları, geliştiricilerin işleri önem veya aciliyet düzeylerine göre farklı kategorilere **ayırmasına** olanak tanır. macOS, iş parçacığı önceliklerini bu QoS sınıflarına göre otomatik olarak yönetir:

1. **User Interactive:**
   - Bu sınıf, kullanıcıyla etkileşimde olan veya iyi bir kullanıcı deneyimi sunmak için anında sonuç gerektiren görevler içindir. Arayüzün yanıt verebilir kalması için bu görevlere en yüksek öncelik verilir (ör. animasyonlar veya olay işleme).
2. **User Initiated:**
   - Belge açmak veya hesaplama gerektiren bir düğmeye tıklamak gibi, kullanıcının başlattığı ve hemen sonuç beklediği görevler içindir. Öncelikleri yüksektir ancak User Interactive sınıfının altındadır.
3. **Utility:**
   - Uzun süre çalışan ve genellikle ilerleme göstergesi sunan görevler içindir (ör. dosya indirme, veri içe aktarma). Öncelikleri kullanıcı tarafından başlatılan görevlerden düşüktür ve hemen tamamlanmaları gerekmez.
4. **Background:**
   - Kullanıcıya görünmeden arka planda çalışan görevler içindir. Dizin oluşturma, eşitleme veya yedekleme bu görevlere örnektir. En düşük önceliğe sahiptirler ve sistem performansına etkileri azdır.

QoS sınıfları sayesinde geliştiricilerin kesin öncelik numaralarını yönetmesi gerekmez; bunun yerine görevin niteliğine odaklanabilirler. Sistem de CPU kaynaklarını buna göre en uygun şekilde kullanır.

Ayrıca, zamanlayıcının dikkate alacağı bir dizi zamanlama parametresini belirtmek için kullanılan farklı **iş parçacığı zamanlama politikaları** da vardır. Bu işlem `thread_policy_[set/get]` ile yapılabilir. Bu, race condition saldırılarında yararlı olabilir.

## macOS Süreçlerinin Kötüye Kullanımı

macOS, **süreçlerin etkileşim kurması, iletişim kurması ve veri paylaşması** için birçok mekanizma sağlar. Bu mekanizmalar sistemin normal çalışması için gerekli olsa da saldırganlar bunları injection, kod yürütme veya veri erişimi amacıyla kötüye kullanabilir.

### Library Injection

Library Injection, saldırganın **bir süreci kötü amaçlı bir kütüphane yüklemeye zorladığı** bir tekniktir. Kütüphane enjekte edildikten sonra hedef sürecin bağlamında çalışır ve saldırgana süreçle aynı izinleri ve erişimi sağlar.


{{#ref}}
macos-library-injection/
{{#endref}}

### Reflective Mach-O Loading

{{#ref}}
reflective-mach-o-loading.md
{{#endref}}

### Function Hooking

Function Hooking, yazılım kodu içindeki **işlev çağrılarını** veya iletileri **araya girerek yakalamayı** içerir. Saldırgan, işlevleri hook ederek sürecin **davranışını değiştirebilir**, hassas verileri gözlemleyebilir, hatta yürütme akışını kontrol edebilir.


{{#ref}}
macos-function-hooking.md
{{#endref}}

### ARM64/ARM64e Call-Stack Spoofing

Bu sayfada ARM64 unwind üst verileri, arm64e PAC kısıtlamaları ve sentetik çağrı zincirleri ele alınmaktadır.

{{#ref}}
arm64-arm64e-call-stack-spoofing.md
{{#endref}}

### Inter Process Communication

Inter Process Communication (IPC), ayrı süreçlerin **veri paylaşması ve alışverişinde bulunması** için kullanılan farklı yöntemleri ifade eder. IPC birçok meşru uygulamanın temelini oluştururken süreç yalıtımını aşmak, hassas bilgileri sızdırmak veya yetkisiz eylemler gerçekleştirmek için de kötüye kullanılabilir.


{{#ref}}
macos-ipc-inter-process-communication/
{{#endref}}

### Electron Applications Injection

Belirli ortam değişkenleriyle çalıştırılan Electron uygulamaları process injection saldırılarına karşı savunmasız olabilir:


{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

### Chromium Injection

`--load-extension` ve `--use-fake-ui-for-media-stream` flag'leriyle tuş vuruşlarını, trafiği ve çerezleri çalmaya, sayfalara script enjekte etmeye ve benzeri işlemlere olanak sağlayan bir **man in the browser attack** gerçekleştirmek mümkündür:


{{#ref}}
macos-chromium-injection.md
{{#endref}}

### Dirty NIB

NIB dosyaları, bir uygulamadaki **kullanıcı arayüzü (UI) öğelerini ve bunların etkileşimlerini tanımlar**. Ancak **keyfi komutlar çalıştırabilirler** ve **Gatekeeper, bir NIB dosyası değiştirilmişse daha önce çalıştırılmış bir uygulamanın yeniden çalıştırılmasını engellemez**. Bu nedenle keyfi programların keyfi komutlar çalıştırmasını sağlamak için kullanılabilirler:


{{#ref}}
macos-dirty-nib.md
{{#endref}}

### Java Applications Injection

**`_JAVA_OPTIONS`**, **`JAVA_TOOL_OPTIONS`** veya **`JDK_JAVA_OPTIONS`** üzerinden JVM seçenekleri enjekte ederek uygulama başlamadan önce bir Java veya native agent yüklemek mümkündür.


{{#ref}}
macos-java-apps-injection.md
{{#endref}}

### Node.js Injection

**`NODE_OPTIONS`**, `--require` (dosya) veya `--import data:text/javascript,…` (dosyasız, Node ≥ 20.6) üzerinden saldırganın JavaScript kodunu önceden yükler; **`NODE_REPL_EXTERNAL_MODULE`** etkileşimli bir REPL'e modül yükler ve **`ELECTRON_RUN_AS_NODE`** bu özelliklerin tümünü Electron ikili dosyalarında yeniden etkinleştirir.

{{#ref}}
macos-nodejs-applications-injection.md
{{#endref}}

### .Net Applications Injection

`Main` öncesinde **`DOTNET_STARTUP_HOOKS`** aracılığıyla veya ön koşullar mevcutken .NET hata ayıklama işlevselliğini kötüye kullanarak .NET uygulamalarına kod enjekte etmek mümkündür.


{{#ref}}
macos-.net-applications-injection.md
{{#endref}}

### Shell Injection

Etkileşimsiz Bash **`BASH_ENV`** değişkenini okur; etkileşimli POSIX shell'leri **`ENV`** değişkenini okur; zsh **`$ZDOTDIR/.zshenv`** dosyasını okur; fish ise **`XDG_CONFIG_HOME`** veya **`XDG_DATA_DIRS`** altındaki yapılandırmaları okur. Bunların her biri, hedeflenen komuttan önce denetlenen bir başlangıç dosyasını çalıştırabilir. Ayrıca xtrace etkin olduğunda (ör. devralınan **`SHELLOPTS=xtrace`** ile) Bash, **`PS4`** içine yerleştirilen komut ikamesini çalıştırır:

{{#ref}}
macos-bash-applications-injection.md
{{#endref}}

### Shell stdin command smuggling

`/bin/zsh -s` başlatıldığında shell, programı standart girdiden okur. Dolayısıyla güvenilmeyen, yapılandırılmış bir belgeyi önce ayrıştırmadan alt sürecin stdin'ine kopyalayan bir indirici, belgenin tamamını shell kaynak koduna dönüştürmüş olur. Gözlemlenen bir yükleyici, herkese açık bir iCalendar dosyasını anonim bir pipe üzerinden satır satır aktarıyordu. Takvim üst verileri komut olarak çalıştırılamadı; ancak zsh, `DESCRIPTION:` sonrasına yerleştirilmiş çalıştırılabilir satırlara ulaşana kadar devam etti. Bu satırlar sonraki uygulama paketini indirip başlattı. Dosyanın beklenen içerik türüne sahip olması ve güvenilir bir yerde barındırılması bunu güvenli hale getirmedi; tehlikeli sınır, dosyanın baytlarını bir yorumlayıcıya aktarmaktı.<sup>[[5]](#references)</sup>

İlgili aşamalar [Mach-O overlays](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md), [Gatekeeper and quarantine](../macos-security-protections/macos-gatekeeper.md) ve [macOS auto-start locations](../../macos-auto-start-locations.md) bölümlerinde ele alınmaktadır.

### PHP Injection

**`PHPRC`** veya **`PHP_INI_SCAN_DIR`**, hedef script'ten önce **`auto_prepend_file`** çalıştıran, denetlenen PHP yapılandırmalarını yükleyebilir.

[PHP yapılandırması ve `auto_prepend_file` başlangıç injection'ı](macos-interpreter-startup-file-injection.md#php-startup-configuration).

### Lua Injection

Bağımsız Lua yorumlayıcısı, hedef script'i işlemeden önce **`LUA_INIT`** (veya sürüme özel karşılığındaki) kodu ya da bir `@file` dosyasını çalıştırır.

[Lua `LUA_INIT` başlangıç injection'ı (dosya ve satır içi kod)](macos-interpreter-startup-file-injection.md#lua-startup-code).

### R Injection

**`R_PROFILE_USER`** ve **`R_PROFILE`**, R kodu içeren başlangıç profillerinin konumunu değiştirir. **`R_DEFAULT_PACKAGES`** / **`R_SCRIPT_DEFAULT_PACKAGES`** ile bir R kütüphane yolu kullanılarak kurulu bir paket de otomatik yüklenebilir.

{{#ref}}
macos-r-applications-injection.md
{{#endref}}

### Julia Injection

**`JULIA_DEPOT_PATH`**, `config/startup.jl` dosyası otomatik olarak çalıştırılan depot'un konumunu değiştirir.

[Julia `JULIA_DEPOT_PATH` ve `startup.jl` injection'ı](macos-interpreter-startup-file-injection.md#julia-startup-depot).

### Erlang and Elixir Injection

**`ERL_AFLAGS`**, **`ERL_FLAGS`** veya **`ERL_ZFLAGS`**, payload dosyası gerektirmeden bir Erlang VM **`-eval`** ifadesi enjekte edebilir; Elixir iş yükleri de genellikle aynı VM'yi başlatır.

{{#ref}}
macos-erlang-elixir-applications-injection.md
{{#endref}}

### GNU Octave Injection

**`OCTAVE_SITE_INITFILE`** ve **`OCTAVE_VERSION_INITFILE`**, Octave başlangıç script'lerinin konumunu değiştirir.

[GNU Octave başlangıç dosyası injection'ı](macos-interpreter-startup-file-injection.md#gnu-octave-startup-files).

### PowerShell Injection

`pwsh`, platformlar arası bir .NET uygulamasıdır; bu nedenle birkaç ortam değişkeni komut öncesi kod yürütmeye olanak tanır: **`XDG_CONFIG_HOME`**, başlangıçta çalışan profil script'lerinin konumunu değiştirir; **`PSModulePath`** modüllerin otomatik yüklenmesini ele geçirir (yerleştirilen bir `.psm1` içe aktarma sırasında çalışır ve yerleşik cmdlet'leri gölgeleyebilir); .NET'in **`CORECLR_PROFILER`**/**`COR_PROFILER`** ve **`DOTNET_STARTUP_HOOKS`** değişkenleri ise `Main` öncesinde saldırgan kodunu sürece yükler.

{{#ref}}
macos-powershell-applications-injection.md
{{#endref}}

### Perl Injection

Bir Perl script'inin keyfi kod çalıştırmasını sağlayacak farklı seçenekleri şurada inceleyin:


{{#ref}}
macos-perl-applications-injection.md
{{#endref}}

### Ruby Injection

Keyfi script'lerin keyfi kod çalıştırmasını sağlamak için ruby ortam değişkenlerini (**`RUBYOPT`**, **`RUBYLIB`**) kötüye kullanmak da mümkündür:


{{#ref}}
macos-ruby-applications-injection.md
{{#endref}}

### Python Injection

**`PYTHONWARNINGS`** ve standart kütüphanedeki **`BROWSER`** zinciri, uyarı filtresi ayrıştırılırken bir komut çalıştırabilir. Dosya kullanan bir alternatifte `sitecustomize.py`, **`PYTHONPATH`** üzerine yerleştirilir; böylece normal `site` başlatması, hedef script'ten önce bu dosyayı içe aktarır. **`PYTHONBREAKPOINT`**, kod `breakpoint()` noktasına geldiğinde seçilen bir callable/modülü çalıştırır. **`PYTHONSTARTUP`** gibi yalnızca etkileşimli kullanımda geçerli olan değişkenlerin kullanım alanı daha dardır.

**`pyinstaller`** ile derlenen yürütülebilir dosyaların, gömülü bir Python kullanarak çalışsalar bile bu ortam değişkenlerini kullanmayacağını unutmayın.

{{#ref}}
macos-python-applications-injection.md
{{#endref}}

### Vim/Neovim Injection

Normal bir başlangıç sırasında **`VIMINIT`** (ve yedeği olan `EXINIT`) Ex komutları olarak çalıştırılır. Bu nedenle kurban Vim/Neovim'i denetlenen bir ortamla açtığında `:!cmd` / `:call system(...)` kod yürütülmesini sağlar:

{{#ref}}
macos-vim-applications-injection.md
{{#endref}}

Ayrıca Homebrew, Python'ı genellikle `/opt/homebrew` altına kurar; bu konumda yerel `admin` grubunun üyeleri başlatıcıyı değiştirebilir. Bu, ortam değişkeni injection'ı değil, yazılabilir ikili dosyanın ele geçirilmesidir; istismar edilebilir olduğunu varsaymadan önce sahipliği ve ACL'leri doğrulayın.


## Detection

### Shield

[**Shield**](https://github.com/theevilbit/Shield), process injection'ı tespit edip engelleyen, **EndpointSecurity** tabanlı açık kaynaklı bir uygulamadır. Endpoint Security üzerinden hangi sinyallerin gözlemlenebildiğini anlamak için iyi bir başvuru kaynağıdır; çünkü aşağıdaki durumlarda uyarı verir:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- Süreç yürütülürken kullanılan **injection ortam değişkenleri**: `DYLD_INSERT_LIBRARIES`, `CFNETWORK_LIBRARY_PATH`, `RAWCAMERA_BUNDLE_PATH` ve `ELECTRON_RUN_AS_NODE`.
- **`task_for_pid`** çağrıları — bir sürecin başka bir sürecin task port'unu istemesi; bu, o sürece injection uygulamanın ön koşuludur.
- **Electron hata ayıklama argümanları** — `--inspect`, `--inspect-brk` ve `--remote-debugging-port`; bunlar bir Electron uygulamasını hata ayıklama modunda başlatır ve herkesin uygulamaya bağlanıp içinde kod çalıştırmasına olanak tanır.<sup>[[3]](#references)</sup>
- **Ayrıcalık düzeyleri arasında symlink/hardlink oluşturulması** — "normal kullanıcı olarak bağlantıyı oluştur, ayrıcalıklı bir konuma yönlendir" şeklindeki klasik yöntem. **Symlink'ler için uyarı verilebilir ancak oluşturulmaları engellenemez**: EndpointSecurity, bağlantı oluşturulmadan önce hedefini göstermez.

### Diğer süreçlerin yaptığı çağrılar

[**Bu blog yazısında**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html), başka **süreçlere kod enjekte eden süreçler** hakkında bilgi edinmek ve ardından bu diğer süreçle ilgili bilgileri almak için **`task_name_for_pid`** işlevinin nasıl kullanılabileceğini bulabilirsiniz.<sup>[[4]](#references)</sup>

Bu işlevi çağırabilmek için süreci çalıştıranla **aynı uid'ye** veya **root** yetkisine sahip olmanız gerekir (işlev, süreç hakkında bilgi döndürür; kod enjekte etme yöntemi sağlamaz).

{{#include ../../../banners/hacktricks-training.md}}

## References

- [1] [Shield — açık kaynaklı macOS process injection tespiti (GitHub)](https://github.com/theevilbit/Shield)
- [2] [Apple Developer — EndpointSecurity çatısı](https://developer.apple.com/documentation/endpointsecurity)
- [3] [Metnew - Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [4] [Scott Knight - Task değişikliklerini tespit etme](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)
- [5] [Kaspersky Securelist - MacSync macOS hırsızının yeni sürümü kripto meraklılarını ve geliştiricileri hedef alıyor](https://securelist.com/macsync-new-version/121383/)
